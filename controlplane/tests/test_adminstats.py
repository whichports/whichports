"""The service-wide numbers behind the Admin screen.

    python -m pytest tests/test_adminstats.py

Because the owner reads every diff but has said he cannot be relied on to catch a
subtle bug in review, these tests are the review. The
ones carrying the argument:

  - the connection is read only, so nothing here can change the database it is
    reporting on
  - a database missing a table answers zero rather than raising, because the
    table and the rows it would hold arrive together
  - a stamp nothing can parse costs one row from one count and never the page
  - the funnel's four numbers are the subsets they claim to be
  - the silence threshold is the sweep's, not a second copy of it
"""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app import accounts, adminstats, alerts, db, finding_alerts, prober

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
PASSWORD = "correct-horse-battery-9"


@pytest.fixture()
def path(tmp_path):
    return str(tmp_path / "cp.db")


def full(path):
    """A database with every table this module reads, the way the box has it."""
    con = db.connect(path)
    db.init(con)
    accounts.init(con)
    alerts.init(con)
    finding_alerts.init(con)
    prober.init(con)
    con.execute("CREATE TABLE IF NOT EXISTS oidc_identities ("
                " id INTEGER PRIMARY KEY, provider TEXT NOT NULL,"
                " subject TEXT NOT NULL, user_id INTEGER NOT NULL,"
                " created_at TEXT NOT NULL, last_used_at TEXT,"
                " email_shown TEXT, UNIQUE (provider, subject))")
    con.commit()
    return con


def workspace(con, workspace_id):
    if db.workspace_by_id(con, workspace_id) is None:
        con.execute("INSERT INTO workspaces (id, name, created_at)"
                    " VALUES (?, ?, ?)", (workspace_id, f"w{workspace_id}",
                                          NOW.isoformat()))
        con.commit()


def account(con, email, workspace_id=1, created=NOW, last_login=NOW,
            disabled=False):
    workspace(con, workspace_id)
    con.execute(
        "INSERT INTO users (email, password_hash, created_at, workspace_id,"
        " last_login_at, disabled_at) VALUES (?, 'x', ?, ?, ?, ?)",
        (email, created.isoformat() if created else None, workspace_id,
         last_login.isoformat() if last_login else None,
         NOW.isoformat() if disabled else None))
    con.commit()


def host(con, name, workspace_id=1, kind="agent", last_report=NOW,
         revoked=False, paused=False):
    workspace(con, workspace_id)
    con.execute(
        "INSERT INTO hosts (name, token_hash, kind, created_at, last_report_at,"
        " workspace_id, revoked_at, paused) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (name, f"t-{name}" if kind == "agent" else None, kind, NOW.isoformat(),
         last_report.isoformat() if last_report else None, workspace_id,
         NOW.isoformat() if revoked else None, 1 if paused else 0))
    con.commit()
    return con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]


# ============================================================ nothing to count

def test_an_empty_database_answers_zero_everywhere(path):
    full(path).close()
    stats = adminstats.collect(path, now=NOW)
    assert stats["accounts"]["total"] == 0
    assert stats["servers"]["total"] == 0
    assert stats["activity"]["documents_total"] == 0
    assert stats["newest"] == []


def test_a_database_with_only_the_core_tables_still_answers(path):
    """The sweep, the prober and provider sign-in each create their own
    tables. A box where none of them has ever run must still render."""
    con = db.connect(path)
    db.init(con)
    accounts.init(con)
    con.close()
    stats = adminstats.collect(path, now=NOW)
    assert stats["activity"]["alerts_open"] == 0
    assert stats["activity"]["probe_runs_total"] == 0
    assert stats["accounts"]["providers"] == {}


def test_a_missing_table_is_not_created_by_reading(path):
    """The read-only connection is what makes this true, and it is worth
    stating: a reporting screen must not be what brings a table into being."""
    con = db.connect(path)
    db.init(con)
    accounts.init(con)
    con.close()
    adminstats.collect(path, now=NOW)
    con = db.connect(path)
    names = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    con.close()
    assert "alerts" not in names
    assert "probe_runs" not in names


def test_the_connection_refuses_to_write(path, monkeypatch):
    """Two halves, because either alone could pass while the other is wrong:
    what `collect` asks sqlite3 to open, and what that request actually
    refuses."""
    full(path).close()
    asked = []
    real = sqlite3.connect

    def spy(target, *args, **kwargs):
        asked.append(target)
        return real(target, *args, **kwargs)

    monkeypatch.setattr(adminstats.sqlite3, "connect", spy)
    adminstats.collect(path, now=NOW)
    assert asked and all("mode=ro" in str(t) for t in asked)

    con = sqlite3.connect(asked[0], uri=True)
    try:
        with pytest.raises(sqlite3.OperationalError):
            con.execute("INSERT INTO workspaces (id, name, created_at)"
                        " VALUES (99, 'x', 'y')")
    finally:
        con.close()


# ==================================================================== accounts

def test_accounts_are_counted_by_what_became_of_them(path):
    con = full(path)
    account(con, "today@example.com", created=NOW, last_login=NOW)
    account(con, "lastweek@example.com", created=NOW - timedelta(days=10),
            last_login=NOW - timedelta(days=10))
    account(con, "never@example.com", created=NOW - timedelta(days=2),
            last_login=None)
    account(con, "gone@example.com", created=NOW - timedelta(days=2),
            disabled=True)
    con.close()
    numbers = adminstats.collect(path, now=NOW)["accounts"]
    assert numbers["total"] == 4
    assert numbers["new_week"] == 3
    assert numbers["new_month"] == 4
    assert numbers["never_signed_in"] == 1
    # today and gone. lastweek signed in ten days ago and never has not
    # signed in at all. Disabling does not erase the last sign-in.
    assert numbers["signed_in_week"] == 2
    assert numbers["disabled"] == 1


def test_two_factor_is_counted_only_when_it_is_confirmed(path):
    """A started-and-abandoned enrolment is off, the same rule
    `accounts.totp_enabled` applies."""
    con = full(path)
    account(con, "on@example.com")
    account(con, "half@example.com")
    con.execute("UPDATE users SET totp_secret = 'S', totp_enabled_at = ?"
                " WHERE email = 'on@example.com'", (NOW.isoformat(),))
    con.execute("UPDATE users SET totp_secret = 'S'"
                " WHERE email = 'half@example.com'")
    con.commit()
    con.close()
    assert adminstats.collect(path, now=NOW)["accounts"]["two_factor"] == 1


def test_a_provider_nobody_uses_gets_no_entry(path):
    con = full(path)
    account(con, "one@example.com")
    account(con, "two@example.com")
    for subject, user_id in (("s1", 1), ("s2", 2)):
        con.execute("INSERT INTO oidc_identities (provider, subject, user_id,"
                    " created_at) VALUES ('google', ?, ?, ?)",
                    (subject, user_id, NOW.isoformat()))
    con.commit()
    con.close()
    assert adminstats.collect(path, now=NOW)["accounts"]["providers"] == {"google": 2}


def test_two_identities_on_one_account_count_once(path):
    con = full(path)
    account(con, "one@example.com")
    for provider in ("google", "microsoft"):
        con.execute("INSERT INTO oidc_identities (provider, subject, user_id,"
                    " created_at) VALUES (?, 's', 1, ?)",
                    (provider, NOW.isoformat()))
    con.commit()
    con.close()
    providers = adminstats.collect(path, now=NOW)["accounts"]["providers"]
    assert providers == {"google": 1, "microsoft": 1}


def test_an_unparseable_created_stamp_costs_one_row_and_not_the_page(path):
    con = full(path)
    account(con, "fine@example.com")
    account(con, "broken@example.com")
    con.execute("UPDATE users SET created_at = 'not a date'"
                " WHERE email = 'broken@example.com'")
    con.commit()
    con.close()
    numbers = adminstats.collect(path, now=NOW)["accounts"]
    assert numbers["total"] == 2
    assert numbers["new_week"] == 1


# ====================================================================== funnel

def test_the_funnel_narrows(path):
    con = full(path)
    for i in (1, 2, 3, 4):
        workspace(con, i)
    host(con, "reported-and-probed", workspace_id=1)
    host(con, "reported-only", workspace_id=2)
    host(con, "added-only", workspace_id=3, last_report=None)
    probed = con.execute("SELECT id FROM hosts WHERE name = 'reported-and-probed'"
                         ).fetchone()[0]
    con.execute("INSERT INTO probe_runs (host_id, vantage, started_at)"
                " VALUES (?, 'probe1', ?)", (probed, NOW.isoformat()))
    con.commit()
    con.close()
    numbers = adminstats.collect(path, now=NOW)["workspaces"]
    assert numbers == {"total": 4, "with_server": 3, "with_report": 2,
                       "with_probe": 1}


def test_a_revoked_server_takes_its_workspace_out_of_the_funnel(path):
    con = full(path)
    workspace(con, 2)
    host(con, "gone", workspace_id=2, revoked=True)
    con.close()
    numbers = adminstats.collect(path, now=NOW)["workspaces"]
    assert numbers["total"] == 2
    assert numbers["with_server"] == 0


# ===================================================================== servers

def test_servers_by_kind_and_by_whether_they_are_talking(path):
    con = full(path)
    host(con, "fresh")
    host(con, "quiet", last_report=NOW - timedelta(
        seconds=alerts.SILENT_AFTER_SECONDS + 60))
    host(con, "new", last_report=None)
    host(con, "an-address", kind="address", last_report=None)
    host(con, "held", paused=True)
    host(con, "removed", revoked=True)
    con.close()
    numbers = adminstats.collect(path, now=NOW)["servers"]
    assert numbers["total"] == 5
    assert numbers["revoked"] == 1
    assert numbers["agent"] == 4
    assert numbers["address"] == 1
    assert numbers["reporting"] == 2
    assert numbers["silent"] == 1
    assert numbers["never_reported"] == 2
    assert numbers["paused"] == 1


def test_the_silence_threshold_is_the_sweeps_own(path):
    """One second inside is reporting, one second past is silent, and the
    number comes from `app/alerts.py` so the screen and the sweep cannot
    disagree about which hosts are quiet."""
    con = full(path)
    host(con, "inside", last_report=NOW - timedelta(
        seconds=alerts.SILENT_AFTER_SECONDS - 1))
    host(con, "past", last_report=NOW - timedelta(
        seconds=alerts.SILENT_AFTER_SECONDS + 1))
    con.close()
    numbers = adminstats.collect(path, now=NOW)["servers"]
    assert (numbers["reporting"], numbers["silent"]) == (1, 1)


def test_an_unparseable_report_stamp_counts_as_never_reported(path):
    con = full(path)
    host(con, "broken")
    con.execute("UPDATE hosts SET last_report_at = 'whenever'")
    con.commit()
    con.close()
    assert adminstats.collect(path, now=NOW)["servers"]["never_reported"] == 1


# ==================================================================== activity

def test_documents_are_counted_in_two_windows_and_in_total(path):
    con = full(path)
    host_id = host(con, "one")
    for hours in (1, 5, 30, 24 * 9):
        con.execute("INSERT INTO reports (host_id, received_at,"
                    " collected_at_unix, schema_version, document)"
                    " VALUES (?, ?, 0, 1, '{}')",
                    (host_id, (NOW - timedelta(hours=hours)).isoformat()))
    con.commit()
    con.close()
    numbers = adminstats.collect(path, now=NOW)["activity"]
    assert numbers["documents_day"] == 2
    assert numbers["documents_week"] == 3
    assert numbers["documents_total"] == 4


def test_open_alerts_are_counted_and_resolved_ones_are_not(path):
    con = full(path)
    host_id = host(con, "one")
    alerts.raise_alert(con, host_id, alerts.KIND_SILENT, "quiet", NOW)
    con.commit()
    con.close()
    assert adminstats.collect(path, now=NOW)["activity"]["alerts_open"] == 1
    con = db.connect(path)
    alerts.resolve_alert(con, host_id, alerts.KIND_SILENT, NOW)
    con.commit()
    con.close()
    assert adminstats.collect(path, now=NOW)["activity"]["alerts_open"] == 0


# =============================================================== the list

def test_the_newest_accounts_come_back_newest_first_with_their_servers(path):
    con = full(path)
    account(con, "old@example.com", workspace_id=1,
            created=NOW - timedelta(days=5))
    account(con, "new@example.com", workspace_id=2, created=NOW)
    host(con, "a", workspace_id=1)
    host(con, "b", workspace_id=1)
    con.close()
    rows = adminstats.collect(path, now=NOW)["newest"]
    assert [r["email"] for r in rows] == ["new@example.com", "old@example.com"]
    assert rows[0]["servers"] == 0
    assert rows[1]["servers"] == 2


def test_the_accounts_list_is_whole_and_the_total_is_its_length(path):
    """Capped at 25 until 2026-10-07: the screen showed its first rows with
    a hint of more and no way to the rest. The list is whole now, newest
    first (docs/screens/admin/SPEC.md, his `yes admin`)."""
    con = full(path)
    for i in range(30):
        account(con, f"a{i:03d}@example.com",
                created=NOW - timedelta(minutes=i))
    con.close()
    stats = adminstats.collect(path, now=NOW)
    assert len(stats["newest"]) == 30
    assert stats["accounts_total"] == 30
    assert stats["newest"][0]["email"] == "a000@example.com"


def test_a_revoked_server_is_not_counted_against_its_workspace(path):
    con = full(path)
    account(con, "one@example.com")
    host(con, "live")
    host(con, "gone", revoked=True)
    con.close()
    assert adminstats.collect(path, now=NOW)["newest"][0]["servers"] == 1


# ================================================================ the gate word

def test_the_signup_mode_comes_from_the_module_that_owns_it(path, monkeypatch):
    full(path).close()
    monkeypatch.setenv("WHICHPORTS_SIGNUP", "open")
    assert adminstats.collect(path, now=NOW)["signups"] == "open"
    monkeypatch.setenv("WHICHPORTS_SIGNUP", "anything else")
    assert adminstats.collect(path, now=NOW)["signups"] == "closed"


# ============================================================ per workspace

def test_a_row_per_workspace_with_what_is_in_it(path):
    con = full(path)
    workspace(con, 2)
    account(con, "one@example.com", workspace_id=1)
    account(con, "two@example.com", workspace_id=2)
    account(con, "three@example.com", workspace_id=2)
    host(con, "fresh", workspace_id=2)
    host(con, "quiet", workspace_id=2, last_report=NOW - timedelta(
        seconds=alerts.SILENT_AFTER_SECONDS + 60))
    con.close()
    rows = {r["id"]: r for r in adminstats.collect(path, now=NOW)["workspace_rows"]}
    assert rows[1]["accounts"] == 1
    assert rows[1]["servers"] == 0
    assert rows[2]["accounts"] == 2
    assert rows[2]["servers"] == 2
    assert rows[2]["reporting"] == 1


def test_the_newest_document_is_the_newest_of_that_workspaces_servers(path):
    con = full(path)
    workspace(con, 2)
    host(con, "older", workspace_id=2, last_report=NOW - timedelta(hours=5))
    host(con, "newer", workspace_id=2, last_report=NOW - timedelta(minutes=2))
    con.close()
    rows = {r["id"]: r for r in adminstats.collect(path, now=NOW)["workspace_rows"]}
    assert rows[2]["last_report_at"] == (NOW - timedelta(minutes=2)).isoformat()


def test_a_workspace_where_nothing_ever_reported_says_nothing(path):
    con = full(path)
    workspace(con, 2)
    host(con, "never", workspace_id=2, last_report=None)
    con.close()
    rows = {r["id"]: r for r in adminstats.collect(path, now=NOW)["workspace_rows"]}
    assert rows[2]["last_report_at"] == ""
    assert rows[2]["servers"] == 1
    assert rows[2]["reporting"] == 0


def test_a_revoked_server_is_in_no_workspace_row(path):
    con = full(path)
    workspace(con, 2)
    host(con, "gone", workspace_id=2, revoked=True)
    con.close()
    rows = {r["id"]: r for r in adminstats.collect(path, now=NOW)["workspace_rows"]}
    assert rows[2]["servers"] == 0


def test_the_rows_are_in_id_order(path):
    con = full(path)
    for i in (5, 2, 3):
        workspace(con, i)
    con.close()
    rows = adminstats.collect(path, now=NOW)["workspace_rows"]
    assert [r["id"] for r in rows] == sorted(r["id"] for r in rows)


def test_a_workspace_carries_its_own_name(path):
    con = full(path)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (7, 'Acme', ?)",
                (NOW.isoformat(),))
    con.commit()
    con.close()
    rows = {r["id"]: r for r in adminstats.collect(path, now=NOW)["workspace_rows"]}
    assert rows[7]["name"] == "Acme"


# ================================ the names behind "never reported"
#
# On 2026-08-28 the real box read seventeen servers, three reporting and
# fourteen never reported, and the screen could say only that. These are the
# tests for the list that answers which ones.

def test_only_servers_that_are_not_reporting_are_listed(path):
    con = full(path)
    host(con, "fine")
    host(con, "never", last_report=None)
    host(con, "quiet", last_report=NOW - timedelta(
        seconds=alerts.SILENT_AFTER_SECONDS + 60))
    con.close()
    rows, total = adminstats.collect(path, now=NOW)["quiet_servers"], None
    names = {r["name"] for r in rows}
    assert names == {"never", "quiet"}


def test_a_revoked_server_is_not_listed(path):
    """Revoking is the operator saying this is not a server of theirs, and the
    record says abandoned add-server flows are exactly what gets revoked."""
    con = full(path)
    host(con, "gone", revoked=True, last_report=None)
    con.close()
    assert adminstats.collect(path, now=NOW)["quiet_servers"] == []


def test_never_reported_comes_before_silent(path):
    """A server that spoke once and stopped is a different and less urgent
    story than one that never did."""
    con = full(path)
    host(con, "quiet", last_report=NOW - timedelta(
        seconds=alerts.SILENT_AFTER_SECONDS + 60))
    host(con, "never", last_report=None)
    con.close()
    rows = adminstats.collect(path, now=NOW)["quiet_servers"]
    assert [r["name"] for r in rows] == ["never", "quiet"]


def test_oldest_first_inside_each_group(path):
    """The one added longest ago and still silent has been wrong for longest."""
    con = full(path)
    for name, days in (("newer", 1), ("oldest", 30), ("middle", 10)):
        con.execute(
            "INSERT INTO hosts (name, token_hash, kind, created_at,"
            " last_report_at, workspace_id) VALUES (?, ?, 'agent', ?, NULL, 1)",
            (name, f"t-{name}", (NOW - timedelta(days=days)).isoformat()))
    con.commit()
    con.close()
    rows = adminstats.collect(path, now=NOW)["quiet_servers"]
    assert [r["name"] for r in rows] == ["oldest", "middle", "newer"]


def test_the_quiet_list_is_whole_and_the_total_is_its_length(path):
    """Capped at 40 until 2026-10-07, for the reason the accounts list was;
    whole now, so every name behind the number is on the screen."""
    con = full(path)
    for i in range(47):
        con.execute(
            "INSERT INTO hosts (name, token_hash, kind, created_at,"
            " last_report_at, workspace_id) VALUES (?, ?, 'agent', ?, NULL, 1)",
            (f"n{i:03d}", f"t{i}", (NOW - timedelta(minutes=i)).isoformat()))
    con.commit()
    con.close()
    stats = adminstats.collect(path, now=NOW)
    assert len(stats["quiet_servers"]) == 47
    assert stats["quiet_servers_total"] == 47


def test_a_row_carries_what_the_screen_needs(path):
    con = full(path)
    workspace(con, 3)
    host(con, "edge", workspace_id=3, kind="address", last_report=None)
    con.close()
    row = adminstats.collect(path, now=NOW)["quiet_servers"][0]
    assert row["name"] == "edge"
    assert row["workspace_id"] == 3
    assert row["kind"] == "address"
    assert row["never"] is True
    assert row["last_report_at"] == ""
    assert row["created_at"]


def test_a_paused_server_that_is_quiet_is_still_listed(path):
    """Pausing stops the alerting, not the reporting, so a paused host that has
    gone quiet is still something to know about."""
    con = full(path)
    host(con, "held", paused=True, last_report=None)
    con.close()
    row = adminstats.collect(path, now=NOW)["quiet_servers"][0]
    assert row["name"] == "held"
    assert row["paused"] is True


# ============================== the watchdog that had no watchdog

def test_the_last_sweep_and_probe_are_reported(path):
    con = full(path)
    host_id = host(con, "one")
    con.execute("INSERT OR REPLACE INTO sweep_state (id, last_sweep_at,"
                " recovered_at) VALUES (1, ?, NULL)",
                ((NOW - timedelta(minutes=4)).isoformat(),))
    con.execute("INSERT INTO probe_runs (host_id, vantage, started_at)"
                " VALUES (?, 'probe1', ?)",
                (host_id, (NOW - timedelta(hours=2)).isoformat()))
    con.commit()
    con.close()
    watchdog = adminstats.collect(path, now=NOW)["watchdog"]
    assert watchdog["sweep"] == (NOW - timedelta(minutes=4)).isoformat()
    assert watchdog["probe"] == (NOW - timedelta(hours=2)).isoformat()


def test_the_newest_probe_run_is_the_one_reported(path):
    con = full(path)
    host_id = host(con, "one")
    for hours in (9, 1, 5):
        con.execute("INSERT INTO probe_runs (host_id, vantage, started_at)"
                    " VALUES (?, 'probe1', ?)",
                    (host_id, (NOW - timedelta(hours=hours)).isoformat()))
    con.commit()
    con.close()
    watchdog = adminstats.collect(path, now=NOW)["watchdog"]
    assert watchdog["probe"] == (NOW - timedelta(hours=1)).isoformat()


def test_a_job_that_never_ran_says_nothing_rather_than_guessing(path):
    """Empty, and the renderer turns that into `never`. A screen that invented
    a time here would be worse than one that says nothing."""
    full(path).close()
    watchdog = adminstats.collect(path, now=NOW)["watchdog"]
    assert watchdog == {"sweep": "", "probe": "", "vantages": []}


def test_a_database_without_the_sweep_table_still_answers(path):
    con = db.connect(path)
    db.init(con)
    con.close()
    assert adminstats.collect(path, now=NOW)["watchdog"]["sweep"] == ""


# ============================================ the vantage registry, 2026-09-08


def test_each_registered_vantage_has_its_own_last_pass(path):
    from app import vantages
    con = full(path)
    vantages.init(con)
    host_id = host(con, "one")
    vantages.add(con, "probe1", "root@a", ["185.199.110.1"])
    vantages.add(con, "probe2", "root@b", ["185.199.110.2"])
    vantages.set_enabled(con, "probe2", False)
    for vantage, hours in (("probe1", 1), ("probe2", 30), ("probe1", 9)):
        when = (NOW - timedelta(hours=hours)).isoformat()
        con.execute("INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
                    " VALUES (?, ?, ?, ?)", (host_id, vantage, when, when))
    con.execute("INSERT INTO probe_runs (host_id, vantage, started_at)"
                " VALUES (?, 'probe2', ?)", (host_id, NOW.isoformat()))
    con.commit()
    con.close()
    watchdog = adminstats.collect(path, now=NOW)["watchdog"]
    assert watchdog["vantages"] == [
        {"name": "probe1", "enabled": True,
         "last_run": (NOW - timedelta(hours=1)).isoformat()},
        {"name": "probe2", "enabled": False,
         "last_run": (NOW - timedelta(hours=30)).isoformat()},
    ]
    assert watchdog["probe"] == NOW.isoformat(), "the single stamp is unchanged"


def test_a_registered_vantage_that_never_ran_says_nothing(path):
    from app import vantages
    con = full(path)
    vantages.init(con)
    vantages.add(con, "probe2", "root@b", ["185.199.110.2"])
    con.close()
    watchdog = adminstats.collect(path, now=NOW)["watchdog"]
    assert watchdog["vantages"] == [{"name": "probe2", "enabled": True, "last_run": ""}]


def test_a_database_without_the_registry_answers_no_vantages(path):
    full(path).close()
    assert adminstats.collect(path, now=NOW)["watchdog"]["vantages"] == []


# ================================== the beta's numbers, 2026-10-06 (SPEC.md)
#
# His picks of 4.425: level 2 (read only, plus Done, plus the stamp of a
# key's use) and the lookup by address. What these hold: the word for an
# instance comes from its key's last use and the batch is its own column, a
# healthy instance with nothing to probe is not called silent, the lookup
# normalises an address first and reads the log by its index, the thresholds
# travel with the numbers so the renderer holds no second copy, and the page's
# queries are bounded for a hundred instances.

def instance(con, name, key_used=None, batches=(), proofs=(), connects=0):
    """One self-hosted instance with what the box knows of it: when its API
    key was last used, the abuse log rows its batches wrote (vantage, target,
    when, batches), the addresses it proved, and the connects charged this
    hour. Returns its id."""
    from app import authz, instances, proberapi
    authz.init(con)
    instances.init(con)
    proberapi.init(con)
    issued = instances.add(con, name, now=NOW - timedelta(days=1),
                           origin=authz.ORIGIN_INVITED)
    if key_used is not None:
        con.execute("UPDATE probe_instance_keys SET last_used_at = ? WHERE instance_id = ?"
                    " AND kind = 'api'", (key_used.isoformat(), issued.instance.id))
    for vantage, target, when, count in batches:
        con.execute(
            "INSERT INTO prober_api_log (instance_id, vantage, target, day,"
            " first_at, last_at, batches, connects) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (issued.instance.id, vantage, target, when.isoformat()[:10],
             when.isoformat(), when.isoformat(), count, 6 * count))
    for address in proofs:
        challenge = authz.start_proof(con, address, authz.METHOD_DNS_TXT,
                                      account=issued.instance.account, now=NOW)
        result = authz.verify_proof(con, challenge.id, now=NOW,
                                    resolver=lambda name, c=challenge: [c.token])
        assert result.recorded, result.reason
    if connects:
        con.execute("INSERT INTO prober_api_charges (instance_id, connects, submitted_at)"
                    " VALUES (?, ?, ?)", (issued.instance.id, connects,
                                          (NOW - timedelta(minutes=5)).isoformat()))
    con.commit()
    return issued.instance.id


V4 = "185.199.108.153"
OTHER_V4 = "185.199.108.154"


def test_an_instance_row_carries_last_seen_last_batch_proofs_targets_and_connects(path):
    con = full(path)
    instance(con, "oakhill", key_used=NOW - timedelta(minutes=3),
             batches=[("probe1", V4, NOW - timedelta(hours=2), 8),
                      ("probe2", V4, NOW - timedelta(hours=1), 8),
                      ("probe1", OTHER_V4, NOW - timedelta(days=2), 3)],
             proofs=[V4], connects=96)
    con.close()
    rows = adminstats.collect(path, now=NOW)["instances"]
    assert len(rows) == 1
    row = rows[0]
    assert row["name"] == "oakhill"
    assert row["last_used_at"] == (NOW - timedelta(minutes=3)).isoformat()
    assert row["last_batch_at"] == (NOW - timedelta(hours=1)).isoformat()
    assert row["proofs"] == 1
    assert row["targets_today"] == 1, "OTHER_V4 was two days ago"
    assert row["connects_hour"] == 96
    assert row["revoked_at"] is None


def test_the_batch_is_its_own_fact_and_a_key_never_used_says_so(path):
    """An instance with nothing to probe sends no batch (dispatch.py 558) but
    its worker syncs our prober list every fifteen minutes through the same
    key check, so the key's use is the heartbeat and the batch a second fact.
    Neither invents the other."""
    con = full(path)
    instance(con, "quiet", key_used=NOW - timedelta(minutes=3))
    instance(con, "never")
    con.close()
    rows = {r["name"]: r for r in adminstats.collect(path, now=NOW)["instances"]}
    assert rows["quiet"]["last_used_at"] == (NOW - timedelta(minutes=3)).isoformat()
    assert rows["quiet"]["last_batch_at"] == ""
    assert rows["quiet"]["proofs"] == 0 and rows["quiet"]["targets_today"] == 0
    assert rows["never"]["last_used_at"] == ""
    assert rows["never"]["last_batch_at"] == ""


def test_a_revoked_instance_stays_in_the_list_with_its_day(path):
    """4.217's abuse log is answered by name, so a revoked row stays."""
    from app import instances
    con = full(path)
    instance(con, "gone", key_used=NOW - timedelta(days=3))
    instances.revoke(con, "gone", now=NOW - timedelta(days=2))
    con.close()
    rows = adminstats.collect(path, now=NOW)["instances"]
    assert rows[0]["name"] == "gone"
    assert rows[0]["revoked_at"] == (NOW - timedelta(days=2)).isoformat()
    assert rows[0]["proofs"] == 0, "revoking ends every proof"


def test_an_instance_row_carries_its_keys_days_and_never_a_hash(path):
    con = full(path)
    instance(con, "oakhill", key_used=NOW)
    con.close()
    row = adminstats.collect(path, now=NOW)["instances"][0]
    kinds = sorted(k["kind"] for k in row["keys"])
    assert kinds == ["api", "proof"]
    for k in row["keys"]:
        assert set(k) == {"kind", "created_at", "revoked_at"}
    assert "hash" not in str(row)


def test_the_instance_log_is_the_last_seven_days_per_vantage(path):
    con = full(path)
    instance(con, "oakhill", batches=[
        ("probe1", V4, NOW - timedelta(days=1), 8),
        ("probe1", OTHER_V4, NOW - timedelta(days=1), 2),
        ("probe2", V4, NOW - timedelta(days=3), 5),
        ("probe1", V4, NOW - timedelta(days=9), 7),
    ])
    con.close()
    row = adminstats.collect(path, now=NOW)["instances"][0]
    assert row["log"] == [
        {"vantage": "probe1", "targets": 2, "batches": 10, "connects": 60},
        {"vantage": "probe2", "targets": 1, "batches": 5, "connects": 30},
    ]


def test_a_failed_batch_still_on_the_box_is_named_with_its_class(path):
    con = full(path)
    instance_id = instance(con, "oakhill")
    con.execute("INSERT INTO prober_api_batches (id, instance_id, vantage, request,"
                " submitted_at, started_at, finished_at, failure)"
                " VALUES ('b1', ?, 'probe2', '{}', ?, ?, ?, 'vantage_unreachable')",
                (instance_id, (NOW - timedelta(minutes=4)).isoformat(),
                 (NOW - timedelta(minutes=3)).isoformat(),
                 (NOW - timedelta(minutes=2)).isoformat()))
    con.commit()
    con.close()
    row = adminstats.collect(path, now=NOW)["instances"][0]
    assert row["failure"] == {"error": "vantage_unreachable", "vantage": "probe2",
                              "at": (NOW - timedelta(minutes=2)).isoformat()}
    assert row["last_batch_at"] == (NOW - timedelta(minutes=4)).isoformat(), \
        "a batch still on the box counts as the last batch when it is newer than the log"


def test_an_instance_without_a_failure_says_none(path):
    con = full(path)
    instance(con, "oakhill")
    con.close()
    assert adminstats.collect(path, now=NOW)["instances"][0]["failure"] is None


def test_a_database_without_the_instance_tables_answers_no_instances(path):
    full(path).close()
    assert adminstats.collect(path, now=NOW)["instances"] == []


def test_the_beta_list_is_counted_and_listed_newest_first(path):
    from app import betasignup
    con = full(path)
    betasignup.init(con)
    for email, servers, days in (("ops@example.net", "6-20", 3),
                                 ("owner@example.com", "", 1),
                                 ("admin@example.org", "100+", 2)):
        con.execute("INSERT INTO beta_signups (email, servers, created_at) VALUES (?, ?, ?)",
                    (email, servers or None, (NOW - timedelta(days=days)).isoformat()))
    con.commit()
    con.close()
    beta = adminstats.collect(path, now=NOW)["beta"]
    assert [r["email"] for r in beta["rows"]] == ["owner@example.com", "admin@example.org",
                                                  "ops@example.net"]
    assert beta["rows"][0]["servers"] == ""
    assert beta["rows"][1]["servers"] == "100+"
    assert beta["total"] == 3


def test_a_database_without_the_beta_table_answers_nobody(path):
    full(path).close()
    assert adminstats.collect(path, now=NOW)["beta"] == {"rows": [], "total": 0}


def test_the_address_lookup_normalises_first_and_reads_the_log_newest_first(path):
    con = full(path)
    instance(con, "oakhill", batches=[("probe1", "2606:50c0:8000::153", NOW - timedelta(days=1), 4),
                                      ("probe2", "2606:50c0:8000::153", NOW, 2)])
    con.close()
    found = adminstats.address_lookup(path, " 2606:50C0:8000:0:0:0:0:153 ")
    assert found["address"] == "2606:50c0:8000::153"
    assert found["error"] == ""
    assert [(r["instance"], r["vantage"]) for r in found["rows"]] == [
        ("oakhill", "probe2"), ("oakhill", "probe1")]
    assert set(found["rows"][0]) == {"instance", "vantage", "day", "first_at", "last_at",
                                     "batches", "connects"}


def test_the_lookup_says_when_nothing_named_the_address_and_keeps_it_nowhere(path):
    con = full(path)
    instance(con, "oakhill")
    con.close()
    found = adminstats.address_lookup(path, V4)
    assert found == {"address": V4, "error": "", "rows": []}
    con = sqlite3.connect(path)
    for table in ("prober_api_log", "prober_api_batches", "prober_api_charges"):
        assert con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    con.close()


@pytest.mark.parametrize("bad", ["", "not-an-address", "10.0.0.1", "fe80::1%eth0",
                                 "185.199.108.153/32", "x" * 300])
def test_the_lookup_refuses_what_is_not_a_public_address_with_one_word(path, bad):
    full(path).close()
    found = adminstats.address_lookup(path, bad)
    assert found["error"] == "not an address" and found["rows"] == []


def test_the_thresholds_travel_with_the_numbers_and_are_the_timers_own(path):
    """The renderer cannot import this tree, so the two thresholds go with the
    numbers. 35 minutes is the sweep's own silence threshold; eleven minutes
    is two sweep timer periods of five with their thirty seconds of random
    delay (controlplane/ops/whichports-sweep.timer)."""
    full(path).close()
    thresholds = adminstats.collect(path, now=NOW)["thresholds"]
    assert thresholds == {"silent_after": alerts.SILENT_AFTER_SECONDS,
                          "sweep_stale": adminstats.SWEEP_STALE_SECONDS}
    assert alerts.SILENT_AFTER_SECONDS == 35 * 60
    assert adminstats.SWEEP_STALE_SECONDS == 11 * 60


def test_open_feedback_is_counted_and_a_box_without_the_table_says_zero(path):
    con = full(path)
    con.execute("CREATE TABLE feedback (id INTEGER PRIMARY KEY, instance_id INTEGER,"
                " workspace_id INTEGER, kind TEXT NOT NULL, words TEXT NOT NULL,"
                " screen TEXT NOT NULL, instance_version TEXT NOT NULL,"
                " received_at TEXT NOT NULL, done_at TEXT)")
    for done in (None, NOW.isoformat(), None):
        con.execute("INSERT INTO feedback (workspace_id, kind, words, screen,"
                    " instance_version, received_at, done_at)"
                    " VALUES (1, 'bug', 'w', 'fleet', 'unknown', ?, ?)",
                    (NOW.isoformat(), done))
    con.commit()
    con.close()
    assert adminstats.collect(path, now=NOW)["feedback_open"] == 2
    full(str(path) + ".2").close()
    assert adminstats.collect(str(path) + ".2", now=NOW)["feedback_open"] == 0


def test_the_admin_pages_queries_are_bounded_for_a_hundred_instances(path):
    """One query per table, never one per instance: a hundred instances with
    a week of log rows each and the whole collection under a second, the
    bound 4.194 held the dashboard to."""
    import time
    con = full(path)
    for i in range(100):
        instance(con, f"inst{i:03d}", key_used=NOW - timedelta(minutes=i % 50),
                 batches=[("probe1", f"185.199.{i // 256 + 108}.{i % 256}",
                           NOW - timedelta(days=d), 7) for d in range(7)],
                 connects=100)
    con.close()
    started = time.perf_counter()
    stats = adminstats.collect(path, now=NOW)
    took = time.perf_counter() - started
    assert len(stats["instances"]) == 100
    assert took < 1.0, f"collect took {took:.2f}s for a hundred instances"


def test_the_proof_count_is_live_for_accounts_own(path):
    """One query over every account, held to the rule `authz.live_for_account`
    decides by: a revoked proof, an expired one and one on a revoked host are
    not counted, a live one is."""
    from app import authz
    con = full(path)
    instance_id = instance(con, "oakhill", proofs=[V4, OTHER_V4])
    account = authz.account_for_instance(instance_id)
    con.execute("UPDATE authorizations SET revoked_at = ? WHERE account = ? AND target = ?",
                (NOW.isoformat(), account, OTHER_V4))
    con.commit()
    expected = len(authz.live_for_account(con, account, now=NOW))
    con.close()
    row = adminstats.collect(path, now=NOW)["instances"][0]
    assert row["proofs"] == expected == 1


def test_the_quiet_list_has_as_many_rows_as_the_silent_and_never_reported_cards(path):
    """The Servers tab's cards and its Not reporting list come from one
    database and must agree on the screen: the list is whole, so its rows
    are the silent and the never-reported counts together, paused and
    revoked ruled the same way on both sides."""
    con = full(path)
    host(con, "fresh", last_report=NOW - timedelta(minutes=3))
    host(con, "quiet", last_report=NOW - timedelta(hours=3))
    host(con, "quieter", last_report=NOW - timedelta(days=2), paused=True)
    host(con, "never-a", last_report=None)
    host(con, "never-b", last_report=None, workspace_id=2)
    host(con, "gone", last_report=None, revoked=True)
    con.close()
    stats = adminstats.collect(path, now=NOW)
    cards = stats["servers"]
    assert cards["silent"] == 2 and cards["never_reported"] == 2
    assert len(stats["quiet_servers"]) == cards["silent"] + cards["never_reported"]
    assert stats["quiet_servers_total"] == len(stats["quiet_servers"])


def test_the_accounts_list_has_as_many_rows_as_the_workspaces_accounts_add_up_to(path):
    """The Workspaces tab's rows and its Accounts list come from one table:
    the list is whole, so its rows are the workspaces' account counts added
    up, and the funnel's total is the same number."""
    con = full(path)
    account(con, "owner@example.com", workspace_id=1)
    account(con, "ops@example.net", workspace_id=2)
    account(con, "admin@example.org", workspace_id=2)
    account(con, "dev@example.org", workspace_id=3, disabled=True)
    con.close()
    stats = adminstats.collect(path, now=NOW)
    added_up = sum(row["accounts"] for row in stats["workspace_rows"])
    assert added_up == 4
    assert len(stats["newest"]) == added_up == stats["accounts_total"]


def test_feedback_rows_travel_with_the_numbers_open_and_done_newest_first(path):
    """The Feedback tab's rows, as `feedback.listing` gives them, and the
    open count beside them from the same table (docs/screens/feedback/
    BRIEF.md). A box without the table has none."""
    from app import feedback
    con = full(path)
    feedback.init(con)
    a = feedback.Message(kind="bug", words="first", screen="fleet", instance_version="unknown")
    b = feedback.Message(kind="feature", words="second", screen="admin", instance_version="0835a67")
    first = feedback.store(con, a, workspace_id=1, now=NOW - timedelta(hours=2))
    second = feedback.store(con, b, instance_id=3, now=NOW - timedelta(hours=1))
    third = feedback.store(con, a, workspace_id=1, now=NOW - timedelta(days=1))
    assert feedback.mark_done(con, third, now=NOW)
    con.close()
    numbers = adminstats.collect(path, now=NOW)
    assert [r["id"] for r in numbers["feedback"]["open"]] == [second, first]
    assert [r["id"] for r in numbers["feedback"]["done"]] == [third]
    assert numbers["feedback"]["open"][0] == {
        "id": second, "instance_id": 3, "workspace_id": None, "kind": "feature",
        "words": "second", "screen": "admin", "instance_version": "0835a67",
        "received_at": (NOW - timedelta(hours=1)).isoformat(), "done_at": None}
    assert numbers["feedback_open"] == 2
    full(str(path) + ".2").close()
    assert adminstats.collect(str(path) + ".2", now=NOW)["feedback"] == {"open": [], "done": []}
