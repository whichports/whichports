"""The provider's firewalls are read at every sweep (docs/RECORD.md 4.340).

Until 2026-10-03 a stored snapshot was read again once it was an hour old
(4.90). On a real server a firewall deleted at the provider was then still
quoted, seven minutes later, as the reason a port answers (4.330). So the
hour went, and with a read every five minutes came two things this file also
holds: old snapshots are deleted when a new one is stored, and the count of
requests one read costs.
"""
import pathlib
import re
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app import db, hetzner, sweep_cli
from test_hetzner import (FakeOpener, FakeResponse, client, envelope, firewall,
                          http_error, opener_for, server)

T0 = datetime(2026, 10, 3, 21, 0, 0, tzinfo=timezone.utc)
MINUTE = timedelta(minutes=1)
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)

SWEEP_TIMER = (pathlib.Path(__file__).resolve().parent.parent
               / "ops" / "whichports-sweep.timer")

# Hetzner's own API specification, the Rate Limiting section, read
# 2026-10-03: "The default limit is 3600 requests per hour and per Project."
HETZNER_DEFAULT_REQUESTS_PER_HOUR = 3600


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    hetzner.init(connection)
    yield connection
    connection.close()


def a_token(con, workspace_id=1, name="tok-"):
    token_id, _ = hetzner.add_token(con, name + "x" * 20, workspace_id)
    return token_id


# How long after a sweep starts its snapshot is stamped. The real client
# stamps when the answer arrives, so a snapshot is always a little younger
# than the sweep that read it, and the next sweep finds it a little less than
# one interval old. A gate of exactly one interval would skip that sweep.
FETCH_TAKES = timedelta(seconds=8)


class Provider:
    """A client that answers a snapshot stamped a moment after the sweep
    began, or fails the way it is told, and counts how often it was asked."""

    def __init__(self):
        self.calls = 0
        self.now = T0
        self.fail = None
        self.rate_limit = hetzner.RateLimit()
        self.servers = ()

    def fetch_snapshot(self):
        self.calls += 1
        if self.fail is not None:
            raise self.fail
        return hetzner.Snapshot(fetched_at=(self.now + FETCH_TAKES).isoformat(),
                                servers=self.servers, firewalls=())

    def sweep(self, con, now):
        self.now = now
        return sweep_cli.refresh_provider(con, now, lambda token: self)


def rows_of(con, workspace_id=1, token_id=None):
    scope = "" if token_id is None else " AND token_id = %d" % token_id
    return [row["fetched_at"] for row in con.execute(
        "SELECT fetched_at FROM provider_snapshots WHERE workspace_id = ?" + scope
        + " ORDER BY id", (workspace_id,))]


# ------------------------------------------------------------ every sweep reads

def sweep_interval():
    """The sweep's own interval, read from the unit that schedules it."""
    found = re.search(r"^OnUnitActiveSec=(\d+)min$", SWEEP_TIMER.read_text(), re.M)
    assert found, "the sweep's timer no longer says how often it runs"
    return timedelta(minutes=int(found.group(1)))


def test_the_sweep_runs_every_five_minutes():
    """Everything below counts in sweeps. If the timer changes, the counts
    here and the comment on SNAPSHOT_MAX_AGE_SECONDS have to be read again."""
    assert sweep_interval() == 5 * MINUTE


def test_every_timed_sweep_reads_the_provider(con):
    a_token(con)
    provider = Provider()
    interval = sweep_interval()

    for tick in range(12):
        note = provider.sweep(con, T0 + tick * interval)
        assert "provider snapshot refreshed" in note, (tick, note)

    assert provider.calls == 12
    assert hetzner.latest_snapshot(con).fetched_at == (
        T0 + 11 * interval + FETCH_TAKES).isoformat()


def test_a_snapshot_five_minutes_old_is_read_again(con):
    """The other side of test_a_fresh_snapshot_does_not in test_hetzner.py,
    which held five minutes as fresh under the hour."""
    hetzner.store_snapshot(con, hetzner.Snapshot(fetched_at=(T0 - 5 * MINUTE).isoformat()))
    assert hetzner.needs_refresh(con, T0) is True


def test_the_case_that_was_measured_is_read_again(con):
    """4.330: a snapshot twenty-five minutes old was still the one quoted.
    Under the hour it was fresh. It is not any more."""
    hetzner.store_snapshot(con, hetzner.Snapshot(fetched_at=(T0 - 25 * MINUTE).isoformat()))
    assert hetzner.needs_refresh(con, T0, max_age=60 * 60) is False   # the old policy
    assert hetzner.needs_refresh(con, T0) is True


def test_a_sweep_run_by_hand_right_after_another_does_not_read_twice(con):
    a_token(con)
    provider = Provider()
    provider.sweep(con, T0)

    note = provider.sweep(con, T0 + timedelta(seconds=20))

    assert note == "" and provider.calls == 1


def test_what_was_changed_at_the_provider_is_on_the_next_sweep(con):
    """The point of it. A server's firewall goes at the provider between two
    sweeps, and the snapshot the engine reads says so one sweep later."""
    a_token(con)
    provider = Provider()
    provider.servers = ({"id": 7, "name": "web-01", "firewalls": [41]},)
    provider.sweep(con, T0)
    assert hetzner.latest_snapshot(con).servers[0]["firewalls"] == [41]

    provider.servers = ({"id": 7, "name": "web-01", "firewalls": []},)
    provider.sweep(con, T0 + sweep_interval())

    assert hetzner.latest_snapshot(con).servers[0]["firewalls"] == []


# ------------------------------------------------- a read that fails keeps what
# was stored, a refusal for too many requests included

@pytest.mark.parametrize("kind, status", [
    (hetzner.ERROR_NETWORK, None),
    (hetzner.ERROR_UNAUTHORIZED, 401),
    (hetzner.ERROR_RATE_LIMITED, 429),
])
def test_a_failed_read_keeps_the_stored_snapshot_and_is_asked_again(con, kind, status):
    a_token(con)
    provider = Provider()
    provider.sweep(con, T0)
    stored = rows_of(con)

    provider.fail = hetzner.ProviderError(kind, status=status)
    note = provider.sweep(con, T0 + 5 * MINUTE)

    assert note.endswith(f"provider not refreshed: {kind}")
    assert rows_of(con) == stored, "a failed read stored or deleted a snapshot"
    assert hetzner.latest_snapshot(con).fetched_at == (T0 + FETCH_TAKES).isoformat()
    assert hetzner.latest_fetch(con)["error_kind"] == kind
    assert hetzner.latest_fetch(con)["error_status"] == status

    # The next sweep asks again, once, and the answer replaces the old one.
    provider.fail = None
    provider.sweep(con, T0 + 10 * MINUTE)
    assert provider.calls == 3
    assert hetzner.latest_snapshot(con).fetched_at == (
        T0 + 10 * MINUTE + FETCH_TAKES).isoformat()
    assert hetzner.latest_fetch(con)["error_kind"] is None


def test_the_providers_own_refusal_for_too_many_requests_is_typed_and_not_retried(con):
    """Through the real client: a 429 is its own typed kind already, the
    sweep treats it as any failed read, and nothing asks a second time on
    the same tick. The provider said to slow down, and a retry is the one
    thing that must not answer that."""
    token_id = a_token(con)
    opener = FakeOpener(lambda request: http_error(
        429, header_pairs={"RateLimit-Limit": 3600, "RateLimit-Remaining": 0,
                           "RateLimit-Reset": 1791061200}))
    hetzner.store_snapshot(con, hetzner.Snapshot(fetched_at=(T0 - 5 * MINUTE).isoformat()),
                           token_id=token_id)

    note = sweep_cli.refresh_provider(con, T0, lambda token: client(opener, token))

    assert note.endswith("provider not refreshed: " + hetzner.ERROR_RATE_LIMITED)
    assert len(opener.requests) == 1, "the read was tried again after a refusal"
    assert hetzner.latest_snapshot(con).fetched_at == (T0 - 5 * MINUTE).isoformat()
    fetch = hetzner.latest_fetch(con)
    assert (fetch["error_kind"], fetch["error_status"]) == (hetzner.ERROR_RATE_LIMITED, 429)


# --------------------------------------------------- what one read costs

def paged_opener(servers, firewalls):
    """Answers each list a page of PER_PAGE at a time, the way the
    specification's pagination does."""
    def respond(request):
        key = "servers" if "/servers" in request.full_url else "firewalls"
        items = servers if key == "servers" else firewalls
        page = int(re.search(r"[?&]page=(\d+)", request.full_url).group(1))
        start = (page - 1) * hetzner.PER_PAGE
        more = start + hetzner.PER_PAGE < len(items)
        return FakeResponse(envelope(key, items[start:start + hetzner.PER_PAGE],
                                     next_page=page + 1 if more else None))
    return FakeOpener(respond)


@pytest.mark.parametrize("servers, firewalls, requests", [
    (0, 0, 2),        # an empty project still costs one request for each list
    (1, 1, 2),
    (50, 50, 2),      # one page of each: the size the count in the code names
    (51, 50, 3),      # the fifty-first server is a second page
    (50, 51, 3),
    (120, 101, 6),
])
def test_one_read_costs_one_request_for_each_page_of_each_list(servers, firewalls, requests):
    opener = paged_opener([server(id=i + 1, name=f"s{i}") for i in range(servers)],
                          [firewall(id=i + 1, name=f"f{i}") for i in range(firewalls)])

    snapshot = client(opener).fetch_snapshot()

    assert len(opener.requests) == requests
    assert (len(snapshot.servers), len(snapshot.firewalls)) == (servers, firewalls)


def test_a_small_project_costs_24_requests_an_hour():
    opener = opener_for(servers=[server()], firewalls=[firewall()])
    client(opener).fetch_snapshot()
    reads_an_hour = HOUR // sweep_interval()

    assert reads_an_hour == 12
    assert len(opener.requests) * reads_an_hour == 24


def test_the_read_alone_cannot_reach_the_providers_default_limit():
    """A list is read for at most MAX_PAGES pages and then refused, so one
    read is at most twice that many requests. At every sweep that is 960 an
    hour, against 3600. Nothing slows the read down as a project grows: past
    2000 servers or 2000 firewalls it fails as too many pages, as before."""
    most_for_one_read = 2 * hetzner.MAX_PAGES
    reads_an_hour = HOUR // sweep_interval()

    assert most_for_one_read * reads_an_hour == 960
    assert most_for_one_read * reads_an_hour < HETZNER_DEFAULT_REQUESTS_PER_HOUR
    assert hetzner.MAX_PAGES * hetzner.PER_PAGE == 2000


# ------------------------------------------------------------------ the pruning

def store(con, when, workspace_id=1, token_id=None, provider=hetzner.PROVIDER):
    return hetzner.store_snapshot(
        con, hetzner.Snapshot(fetched_at=when if isinstance(when, str) else when.isoformat()),
        provider=provider, workspace_id=workspace_id, token_id=token_id)


def test_a_days_worth_is_kept_and_the_rest_goes_when_a_new_one_is_stored(con):
    token_id = a_token(con)
    for age in (3 * DAY, DAY + MINUTE, DAY - MINUTE, HOUR, 5 * MINUTE):
        con.execute(
            "INSERT INTO provider_snapshots (provider, fetched_at, servers_json,"
            " firewalls_json, workspace_id, token_id) VALUES (?, ?, '[]', '[]', 1, ?)",
            (hetzner.PROVIDER, (T0 - age).isoformat(), token_id))
    con.commit()

    store(con, T0, token_id=token_id)

    assert rows_of(con) == [(T0 - DAY + MINUTE).isoformat(), (T0 - HOUR).isoformat(),
                            (T0 - 5 * MINUTE).isoformat(), T0.isoformat()]


def test_a_day_of_sweeps_leaves_a_days_worth_of_rows(con):
    """288 reads a day. After three days of them the table holds one day's
    and no more, whatever came before."""
    a_token(con)
    provider = Provider()
    interval = sweep_interval()
    ticks = 3 * (DAY // interval)

    for tick in range(ticks):
        provider.sweep(con, T0 + tick * interval)

    kept = rows_of(con)
    last = T0 + (ticks - 1) * interval + FETCH_TAKES
    assert len(kept) == DAY // interval + 1 == 289
    assert kept[-1] == last.isoformat()
    assert kept[0] == (last - DAY).isoformat()


def test_the_snapshot_just_stored_is_never_pruned(con):
    """Even one stamped long before the rows already there, which is a clock
    that stepped back. Nothing is older than a day before it, so nothing
    goes, and it is there to be read."""
    token_id = a_token(con)
    store(con, T0, token_id=token_id)

    new_id = store(con, T0 - 3 * DAY, token_id=token_id)

    assert rows_of(con) == [T0.isoformat(), (T0 - 3 * DAY).isoformat()]
    assert con.execute("SELECT 1 FROM provider_snapshots WHERE id = ?",
                       (new_id,)).fetchone() is not None


def test_another_tokens_and_another_workspaces_rows_are_never_touched(con):
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'other', 't')")
    con.commit()
    mine = a_token(con, 1, "mine-")
    neighbour = a_token(con, 1, "next-")
    theirs = a_token(con, 2, "them-")
    old = T0 - 30 * DAY
    for workspace_id, token_id in ((1, mine), (1, neighbour), (2, theirs)):
        store(con, old, workspace_id=workspace_id, token_id=token_id)

    store(con, T0, workspace_id=1, token_id=mine)

    assert rows_of(con, 1, mine) == [T0.isoformat()]
    assert rows_of(con, 1, neighbour) == [old.isoformat()]
    assert rows_of(con, 2, theirs) == [old.isoformat()]


def test_a_workspace_with_no_token_keeps_its_rows_from_another_such_workspace(con):
    """Two workspaces that hold no token both store under the same stand-in
    for "no token". The workspace is what keeps their rows apart."""
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'other', 't')")
    con.commit()
    old = T0 - 30 * DAY
    store(con, old, workspace_id=1)
    store(con, old, workspace_id=2)
    assert {row[0] for row in con.execute(
        "SELECT token_id FROM provider_snapshots")} == {hetzner.NO_TOKEN}

    store(con, T0, workspace_id=1)

    assert rows_of(con, 1) == [T0.isoformat()]
    assert rows_of(con, 2) == [old.isoformat()]


def test_another_providers_rows_are_never_touched(con):
    token_id = a_token(con)
    old = T0 - 30 * DAY
    con.execute(
        "INSERT INTO provider_snapshots (provider, fetched_at, servers_json,"
        " firewalls_json, workspace_id, token_id) VALUES ('elsewhere', ?, '[]', '[]', 1, ?)",
        (old.isoformat(), token_id))
    con.commit()

    store(con, T0, token_id=token_id)

    assert [row[0] for row in con.execute(
        "SELECT fetched_at FROM provider_snapshots WHERE provider = 'elsewhere'")] == [
            old.isoformat()]


@pytest.mark.parametrize("stamp", ["not a date", "2026-10-01T12:00:00", ""])
def test_a_row_whose_stamp_will_not_read_is_left_where_it_is(con, stamp):
    """It cannot be shown to be older than a day, so it is not deleted. The
    same refusal to guess that needs_refresh makes."""
    token_id = a_token(con)
    store(con, stamp, token_id=token_id)

    store(con, T0, token_id=token_id)

    assert rows_of(con) == [stamp, T0.isoformat()]


@pytest.mark.parametrize("stamp", ["not a date", "2026-10-03T21:00:00"])
def test_a_new_snapshot_whose_own_stamp_will_not_read_prunes_nothing(con, stamp):
    token_id = a_token(con)
    old = T0 - 30 * DAY
    store(con, old, token_id=token_id)

    store(con, stamp, token_id=token_id)

    assert rows_of(con) == [old.isoformat(), stamp]


def test_the_insert_and_the_pruning_are_one_transaction(con, monkeypatch):
    """If the pruning fails, the new snapshot is not stored either, and
    nothing is left half done on the connection for a later commit to carry."""
    token_id = a_token(con)
    old = T0 - 30 * DAY
    store(con, old, token_id=token_id)

    def broken(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(hetzner, "_prune_snapshots", broken)
    with pytest.raises(sqlite3.OperationalError):
        store(con, T0, token_id=token_id)
    con.commit()   # whatever a caller commits next must not bring the insert with it

    assert rows_of(con) == [old.isoformat()]
    assert con.in_transaction is False


def test_storing_works_on_a_connection_that_hands_back_plain_tuples(tmp_path):
    """The site's own tests store a snapshot through a bare sqlite3
    connection, with no row factory. The first version of the pruning read
    its rows by name and failed there, which the gate caught on 2026-10-03
    and no test in this folder did."""
    path = str(tmp_path / "bare.db")
    made = db.connect(path)
    db.init(made)
    hetzner.init(made)
    made.close()
    bare = sqlite3.connect(path)
    old = T0 - 30 * DAY

    hetzner.store_snapshot(bare, hetzner.Snapshot(fetched_at=old.isoformat()))
    hetzner.store_snapshot(bare, hetzner.Snapshot(fetched_at=T0.isoformat()))

    assert [row[0] for row in bare.execute(
        "SELECT fetched_at FROM provider_snapshots ORDER BY id")] == [T0.isoformat()]
    bare.close()


def test_a_failed_read_prunes_nothing(con):
    token_id = a_token(con)
    old = T0 - 30 * DAY
    store(con, old, token_id=token_id)
    provider = Provider()
    provider.fail = hetzner.ProviderError(hetzner.ERROR_NETWORK)

    provider.sweep(con, T0)

    assert rows_of(con) == [old.isoformat()]
