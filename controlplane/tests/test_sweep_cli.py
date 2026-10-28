"""The timer that runs both sweeps and delivers what they raised.

    python -m pytest tests/test_sweep_cli.py

This ran untested until the finding pass arrived, and the change that made a
test necessary is the delivery: there are now two kinds of alert sharing one
table and one retry, and each has its own mail. So the tests here are about the
delivery and not about the wording of a log line.

The two that matter most:

  - **Eight ports moving at once is one message.** Coalescing lives in this
    file rather than in the engine, so it has to be proved from this side.
  - **A failed delivery loses nothing.** Nothing is stamped unless the relay
    accepted the message, and the next run tries the same alerts again.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from app import (alerts, db, finding_alerts, intent, prober, store,
                 sweep_cli)

NOW = datetime(2026, 8, 17, 12, 0, 0, tzinfo=timezone.utc)
DEBOUNCE = timedelta(seconds=finding_alerts.DEBOUNCE_SECONDS)
# When the helpers below add a channel: before anything a test raises. A
# destination hears what is raised after it was added (decided on 26 October
# 2026), and these tests are about other things, so their channels are there
# first, as a channel a person set up before a change is.
ADDED = NOW - timedelta(days=1)


@pytest.fixture()
def dbpath(tmp_path, monkeypatch):
    path = str(tmp_path / "cp.db")
    monkeypatch.setenv(db.DB_ENV, path)
    con = db.connect(path)
    db.init(con)
    prober.init(con)
    intent.init(con)
    alerts.init(con)
    finding_alerts.init(con)
    con.close()
    return path


@pytest.fixture()
def sent(monkeypatch):
    """Every message the run would hand to a relay."""
    out = []

    def fake_send(subject, body, config=None, html=""):
        out.append((subject, body))
        return True, "sent"

    monkeypatch.setattr(sweep_cli.notify, "send", fake_send)
    return out


def con_for(path):
    con = db.connect(path)
    return con


def document(ports):
    return {
        "schema_version": 1, "hostname": "one", "collected_at_unix": 1,
        "sockets": {"status": "collected", "listening": [
            {"protocol": "tcp", "port": port, "family": "v4",
             "bind_address": "0.0.0.0", "process_name": "caddy", "pid": 7}
            for port in ports]},
        "nftables": {"status": "collected", "tables": []},
    }


def probe(con, host_id, results, started_at):
    cur = con.execute(
        "INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
        " VALUES (?, ?, ?, ?)", (host_id, "198.51.100.7", started_at, started_at))
    for port, state in results:
        con.execute(
            "INSERT INTO probe_results (run_id, target, family, port, state,"
            " measured_at) VALUES (?, ?, ?, ?, ?, ?)",
            (cur.lastrowid, "203.0.113.9", "v4", port, state, started_at))
    con.commit()


def a_change_is_due(path, ports=(443,)):
    """Bring the database to the point where a mail about `ports` is due.

    The pass is driven directly so the clock can be moved, then the command is
    run for real. `sweep_cli.main` reads the wall clock, and by then every
    change has already confirmed, so the window is not in the way.
    """
    con = con_for(path)
    host_id, _ = store.add_host(con, "one")
    store.insert_report(con, host_id, 1, 1, json.dumps(document(ports)))
    # The wall clock, because `sweep_cli.main` reads it and a host stamped in
    # the past would raise the dead-man alert as well and put a second message
    # in the way of the one under test.
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), host_id))
    con.commit()
    for port in ports:
        intent.declare(con, "one", "tcp", port, "v4", "open")
    # The probe runs take the wall clock for the same reason `last_report_at`
    # does just above: `sweep_cli.main` reads it, and runs stamped in the past
    # raise the stale-outside-view alert as well, putting a second message in
    # the way of the one under test. The half hour between them is what the
    # finding transition needs and is preserved.
    wall = datetime.now(timezone.utc)
    probe(con, host_id, [(port, prober.STATE_CONNECTED) for port in ports],
          (wall - timedelta(minutes=40)).isoformat())
    finding_alerts.evaluate(con, now=NOW)
    probe(con, host_id, [(port, prober.STATE_NO_RESPONSE) for port in ports],
          (wall - timedelta(minutes=10)).isoformat())
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    con.close()
    return host_id


# ----------------------------------------------------------------- delivering

def test_eight_ports_moving_at_once_leave_in_one_message(dbpath, sent):
    ports = tuple(range(8000, 8008))
    a_change_is_due(dbpath, ports)
    assert sweep_cli.main([]) == 0

    assert len(sent) == 1
    subject, body = sent[0]
    assert subject == "[whichports] 8 ports changed on one"
    assert "8000, 8001, 8002, 8003, 8004 and 3 more" in body


def test_every_alert_in_the_group_is_stamped_together(dbpath, sent):
    ports = tuple(range(8000, 8008))
    a_change_is_due(dbpath, ports)
    sweep_cli.main([])

    con = con_for(dbpath)
    rows = con.execute("SELECT notified_at FROM alerts WHERE kind = ?",
                       (finding_alerts.KIND_FINDING,)).fetchall()
    con.close()
    assert len(rows) == 8
    assert all(row["notified_at"] for row in rows)


def test_a_delivered_change_is_not_sent_again(dbpath, sent):
    a_change_is_due(dbpath)
    sweep_cli.main([])
    sweep_cli.main([])
    assert len(sent) == 1


def a_port_became_reachable_under_a_rule(path):
    """fart's case A on the wall clock, because `sweep_cli.main` reads it and
    a notice is due for a day after it was raised: 22 measured, then 3000
    opened with a listener and `ufw allow 3000`, settled past the window."""
    def doc(ports):
        return {
            "schema_version": 1, "hostname": "one", "collected_at_unix": 1,
            "sockets": {"status": "collected", "listening": [
                {"protocol": "tcp", "port": port, "family": "v4",
                 "bind_address": "0.0.0.0", "process_name": "",
                 "unit": f"porttest-{port}.service", "pid": None}
                for port in ports]},
            "nftables": {"status": "collected", "tables": [
                {"family": "ip", "name": "filter", "chains": [
                    {"name": "INPUT", "hook": "input", "priority": 0,
                     "type": "filter", "policy": "drop", "rules": [
                         {"text": "counter jump ufw-user-input",
                          "rendered": "full", "comment": ""}]},
                    {"name": "ufw-user-input", "rules": [
                        {"text": f"ip protocol tcp tcp dport {port} counter accept",
                         "rendered": "full", "comment": ""} for port in ports]}]}]},
        }

    wall = datetime.now(timezone.utc)
    con = con_for(path)
    host_id, _ = store.add_host(con, "one")
    store.insert_report(con, host_id, 1, 1, json.dumps(doc([22])))
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                (wall.isoformat(), host_id))
    con.commit()
    probe(con, host_id, [(22, prober.STATE_CONNECTED)],
          (wall - timedelta(minutes=40)).isoformat())
    finding_alerts.evaluate(con, now=wall - timedelta(minutes=40))
    store.insert_report(con, host_id, 2, 1, json.dumps(doc([22, 3000])))
    probe(con, host_id, [(22, prober.STATE_CONNECTED), (3000, prober.STATE_CONNECTED)],
          (wall - timedelta(minutes=30)).isoformat())
    finding_alerts.evaluate(con, now=wall - timedelta(minutes=30))
    told = finding_alerts.evaluate(con, now=wall - timedelta(minutes=10))
    con.close()
    assert told["told"] == ["one tcp/3000 v4"]


def test_a_port_that_became_reachable_under_a_rule_is_mailed_once(dbpath, sent):
    """The mail the 2026-09-26 test never received (docs/RECORD.md 4.200),
    through the real delivery, stamped, and not sent twice."""
    a_port_became_reachable_under_a_rule(dbpath)
    sweep_cli.main([])
    sweep_cli.main([])

    assert len(sent) == 1
    subject, body = sent[0]
    assert subject == "[whichports] Port 3000 on one became reachable from the internet"
    assert "  program: porttest-3000\n" in body
    con = con_for(dbpath)
    row = con.execute("SELECT * FROM alerts WHERE kind = ?",
                      (finding_alerts.KIND_FINDING,)).fetchone()
    con.close()
    assert row["notified_at"] is not None
    assert row["resolved_at"] is not None


def test_the_dry_run_counts_a_notice_as_a_mail_it_would_send(dbpath, sent, capsys):
    a_port_became_reachable_under_a_rule(dbpath)
    sweep_cli.main(["--dry-run"])
    assert "would send: one, 1 findings changed" in capsys.readouterr().out
    assert sent == []


def test_a_failed_delivery_loses_nothing_and_is_retried(dbpath, monkeypatch):
    attempts = []

    def refuse(subject, body, config=None, html=""):
        attempts.append(subject)
        return False, "OSError"

    monkeypatch.setattr(sweep_cli.notify, "send", refuse)
    a_change_is_due(dbpath)
    assert sweep_cli.main([]) == 0
    assert sweep_cli.main([]) == 0
    assert len(attempts) == 2

    con = con_for(dbpath)
    rows = con.execute("SELECT * FROM alerts WHERE kind = ?",
                       (finding_alerts.KIND_FINDING,)).fetchall()
    con.close()
    assert len(rows) == 1
    assert rows[0]["notified_at"] is None


def test_a_silence_and_a_finding_are_two_different_messages(dbpath, sent):
    host_id = a_change_is_due(dbpath)
    con = con_for(dbpath)
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                ((datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
                 host_id))
    con.commit()
    con.close()

    sweep_cli.main([])

    subjects = sorted(subject for subject, _ in sent)
    assert len(subjects) == 2
    assert any("stopped reporting" in subject for subject in subjects)
    assert any("Port 443 on one" in subject for subject in subjects)


def test_a_muted_server_delivers_nothing(dbpath, sent):
    con = con_for(dbpath)
    store.add_host(con, "one")
    finding_alerts.mute_host(con, "one", now=datetime.now(timezone.utc))
    con.close()
    a_change_is_due_for_muted(dbpath)

    assert sweep_cli.main([]) == 0
    assert sent == []


def a_change_is_due_for_muted(path):
    """The same setup as a_change_is_due, on a host that already exists."""
    con = con_for(path)
    host_id = con.execute("SELECT id FROM hosts WHERE name = 'one'").fetchone()["id"]
    store.insert_report(con, host_id, 1, 1, json.dumps(document([443])))
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), host_id))
    con.commit()
    intent.declare(con, "one", "tcp", 443, "v4", "open")
    # Wall clock, for the reason a_change_is_due spells out.
    wall = datetime.now(timezone.utc)
    probe(con, host_id, [(443, prober.STATE_CONNECTED)],
          (wall - timedelta(minutes=40)).isoformat())
    finding_alerts.evaluate(con, now=NOW)
    probe(con, host_id, [(443, prober.STATE_NO_RESPONSE)],
          (wall - timedelta(minutes=10)).isoformat())
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    con.close()


# ------------------------------------------------------------------- dry runs

def test_a_dry_run_delivers_nothing(dbpath, sent):
    a_change_is_due(dbpath)
    assert sweep_cli.main(["--dry-run"]) == 0
    assert sent == []

    con = con_for(dbpath)
    row = con.execute("SELECT notified_at FROM alerts WHERE kind = ?",
                      (finding_alerts.KIND_FINDING,)).fetchone()
    con.close()
    assert row["notified_at"] is None


def test_a_dry_run_says_what_it_would_send(dbpath, sent, capsys):
    a_change_is_due(dbpath, (80, 443))
    sweep_cli.main(["--dry-run"])
    printed = capsys.readouterr().out
    assert "would send: one, 2 findings changed" in printed


# ----------------------------------------------------------- nothing to do yet

def test_a_fleet_with_no_probe_run_delivers_nothing(dbpath, sent, capsys):
    """The state of production on 2026-08-17. Three hosts, real documents, no
    probe runs, so every outside view is not tested and this timer has nothing
    it is allowed to say."""
    con = con_for(dbpath)
    for name in ("one", "two", "three"):
        host_id, _ = store.add_host(con, name)
        store.insert_report(con, host_id, 1, 1, json.dumps(document([22, 443])))
        con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                    (datetime.now(timezone.utc).isoformat(), host_id))
        intent.declare(con, name, "tcp", 443, "v4", "closed")
    con.commit()
    con.close()

    assert sweep_cli.main([]) == 0
    assert sent == []
    assert "0 findings changed" in capsys.readouterr().out


def test_an_unknown_alert_kind_is_printed_rather_than_dropped(dbpath, sent, capsys):
    con = con_for(dbpath)
    host_id, _ = store.add_host(con, "one")
    con.execute("INSERT INTO alerts (host_id, kind, detail, raised_at)"
                " VALUES (?, 'something new', 'x', ?)",
                (host_id, NOW.isoformat()))
    con.commit()
    con.close()

    sweep_cli.main([])
    assert "no mail for alerts of kind something new" in capsys.readouterr().out
    assert sent == []


# ============================================ the webhook, the second channel
#
# It hangs off the same pending machinery the mail does, so PRODUCT 4c's rules
# about when to alert are inherited rather than written twice. What has to be
# proved from this side is that the two channels retry independently.


class Posted(list):
    """Every payload the run would put on the wire. A list so the tests read
    like the mail ones, with a switch that makes the endpoint start failing."""

    ok = True

    def fail(self):
        self.ok = False


@pytest.fixture()
def posted(monkeypatch):
    out = Posted()

    def fake_send(payload, config=None, resolver=None, opener=None):
        out.append(payload)
        if out.ok:
            return True, "posted"
        return False, "the endpoint could not be reached: OSError"

    monkeypatch.setattr(sweep_cli.webhook, "send", fake_send)
    return out


@pytest.fixture()
def hooked(monkeypatch):
    monkeypatch.setenv("WHICHPORTS_WEBHOOK_URL", "https://hooks.example.com/x")


def test_no_webhook_configured_posts_nothing(dbpath, sent, posted, monkeypatch):
    monkeypatch.delenv("WHICHPORTS_WEBHOOK_URL", raising=False)
    a_change_is_due(dbpath)
    assert sweep_cli.main([]) == 0
    assert sent, "the mail half stopped working"
    assert posted == []


def test_a_configured_webhook_gets_the_change(dbpath, sent, posted, hooked):
    a_change_is_due(dbpath)
    assert sweep_cli.main([]) == 0
    assert len(posted) == 1
    assert posted[0]["kind"] == "finding changed"
    assert posted[0]["server"] == "one"
    assert len(posted[0]["changes"]) == 1


def test_eight_ports_moving_at_once_is_one_post(dbpath, sent, posted, hooked):
    """The same coalescing the mail gets, and it comes free from sharing the
    queue rather than from being written again here."""
    a_change_is_due(dbpath, ports=(443, 8080, 9000))
    assert sweep_cli.main([]) == 0
    assert len(posted) == 1
    assert len(posted[0]["changes"]) == 3


def test_a_delivered_alert_is_not_posted_twice(dbpath, sent, posted, hooked):
    a_change_is_due(dbpath)
    assert sweep_cli.main([]) == 0
    assert len(posted) == 1
    assert sweep_cli.main([]) == 0
    assert len(posted) == 1, "the second sweep posted the same alert again"


def test_a_failed_post_retries_without_re_sending_the_mail(dbpath, sent, posted, hooked):
    """The whole reason alert_deliveries exists. Before it there was one
    notified_at column and no third option: stamping on any success drops the
    failed channel for ever, and stamping only when both succeed re-sends the
    working one every sweep."""
    a_change_is_due(dbpath)
    posted.fail()
    assert sweep_cli.main([]) == 0
    assert len(sent) == 1, "the mail should have gone once"
    assert len(posted) == 1, "the webhook should have been attempted once"

    # Second sweep: the webhook is retried, the mail is not repeated.
    assert sweep_cli.main([]) == 0
    assert len(sent) == 1, "the mail was sent twice because the webhook failed"
    assert len(posted) == 2, "the failed webhook was not retried"


def test_a_suppressed_alert_never_reaches_the_webhook(dbpath, sent, posted, hooked):
    """A mute suppresses rather than queues (docs/PRODUCT.md 4c), and it has to
    hold on every channel or muting stops meaning anything. Suppressing the
    alert directly, because what is under test is the delivery and not the
    engine's own decision to suppress, which tests/test_finding_alerts.py owns.
    """
    a_change_is_due(dbpath)
    con = con_for(dbpath)
    for row in con.execute("SELECT id FROM alerts").fetchall():
        alerts.suppress_alert(con, row["id"], datetime.now(timezone.utc))
    con.commit()
    con.close()

    assert sweep_cli.main([]) == 0
    assert posted == [], "a suppressed alert was posted to the webhook"
    assert sent == [], "a suppressed alert was mailed"


def test_the_dry_run_posts_nothing(dbpath, sent, posted, hooked):
    a_change_is_due(dbpath)
    assert sweep_cli.main(["--dry-run"]) == 0
    assert posted == []
    assert sent == []


# ================================== channels, and not breaking the live box
#
# `docs/RECORD.md` 4.86. A channel row names the environment variable its
# destination lives in, so a screen can be told a webhook exists without being
# told its URL. The production box is configured by environment alone today, so
# the fallback below is what stops a deploy silently ending delivery.


def a_channel(path, label="ops", env_name="WHICHPORTS_WEBHOOK_URL"):
    con = con_for(path)
    from app import channels
    channels.init(con)
    channel = channels.add(con, channels.TYPE_WEBHOOK, label, env_name, now=ADDED)
    con.close()
    return channel


def test_with_no_rows_the_environment_still_delivers(dbpath, sent, posted, hooked):
    """The box today. A deploy that silently stopped delivering would be the
    monitoring tool failing quietly."""
    a_change_is_due(dbpath)
    assert sweep_cli.main([]) == 0
    assert len(posted) == 1


def test_the_fallback_says_so_every_run(dbpath, sent, posted, hooked, capsys):
    """So it cannot become the permanent arrangement by nobody noticing."""
    a_change_is_due(dbpath)
    sweep_cli.main([])
    assert "no channel rows" in capsys.readouterr().out


def test_one_row_ends_the_fallback_and_its_notice(dbpath, sent, posted, hooked, capsys):
    a_change_is_due(dbpath)
    a_channel(dbpath)
    sweep_cli.main([])
    out = capsys.readouterr().out
    assert "no channel rows" not in out
    assert len(posted) == 1


def test_two_rows_are_two_posts(dbpath, sent, posted, hooked, monkeypatch):
    """The thing the environment alone could never express."""
    monkeypatch.setenv("WHICHPORTS_WEBHOOK_URL_SEC", "https://other.example/h")
    a_change_is_due(dbpath)
    a_channel(dbpath, label="ops")
    a_channel(dbpath, label="security", env_name="WHICHPORTS_WEBHOOK_URL_SEC")
    assert sweep_cli.main([]) == 0
    assert len(posted) == 2


def test_a_channel_switched_off_is_not_posted_to(dbpath, sent, posted, hooked):
    from app import channels
    a_change_is_due(dbpath)
    a_channel(dbpath)
    con = con_for(dbpath)
    channels.set_enabled(con, "ops", False)
    con.close()
    assert sweep_cli.main([]) == 0
    assert posted == []


def test_a_row_whose_variable_is_unset_does_not_fall_back(dbpath, sent, posted, hooked):
    """Rows exist and none can send. That is an answer, not a reason to reach
    for a variable nobody pointed at."""
    a_change_is_due(dbpath)
    a_channel(dbpath, env_name="WHICHPORTS_NOT_SET_ANYWHERE")
    assert sweep_cli.main([]) == 0
    assert posted == [], "it fell back to the environment past a real row"


def test_the_mail_is_untouched_by_any_of_this(dbpath, sent, posted, hooked):
    """Email keeps its own configuration this round. Changing the one channel
    that works while adding a second one is two risks for one PR."""
    a_change_is_due(dbpath)
    a_channel(dbpath)
    assert sweep_cli.main([]) == 0
    assert len(sent) == 1


def test_adding_a_row_for_the_variable_already_in_use_re_posts_nothing(dbpath, sent, posted, hooked):
    """The migration path. The delivery key is the variable a destination is
    read from, so the environment-only arrangement and a row naming that same
    variable are one destination, and adding the row does not re-post what has
    already gone."""
    a_change_is_due(dbpath)
    assert sweep_cli.main([]) == 0
    assert len(posted) == 1

    a_channel(dbpath, env_name="WHICHPORTS_WEBHOOK_URL")
    assert sweep_cli.main([]) == 0
    assert len(posted) == 1, "adding a row re-posted an alert already delivered"


def test_a_row_for_a_different_variable_is_a_different_destination(dbpath, sent, posted, hooked, monkeypatch):
    """And that one has not had it, so it gets it."""
    monkeypatch.setenv("WHICHPORTS_WEBHOOK_URL_SEC", "https://other.example/h")
    a_change_is_due(dbpath)
    assert sweep_cli.main([]) == 0
    assert len(posted) == 1

    a_channel(dbpath, label="security", env_name="WHICHPORTS_WEBHOOK_URL_SEC")
    assert sweep_cli.main([]) == 0
    assert len(posted) == 2


# ============================ the provider snapshot refreshes on this timer
#
# `docs/RECORD.md` 4.90. It rides this sweep rather than getting a unit of its
# own, because a new unit is a new thing to install by hand and this needs the
# environment the sweep already has.


class FakeProviderClient:
    """A provider that answers, or raises the typed kind."""

    def __init__(self, fail=None, remaining=3500):
        self.fail = fail
        self.calls = 0
        self.rate_limit = type("R", (), {"remaining": remaining})()

    def fetch_snapshot(self):
        from app import hetzner
        self.calls += 1
        if self.fail:
            raise self.fail
        return hetzner.Snapshot(
            fetched_at=datetime.now(timezone.utc).isoformat(),
            servers=(), firewalls=())


def test_no_token_fetches_nothing(dbpath):
    """Off unless configured, and that is not an error. It is what a fresh
    install looks like."""
    from app import hetzner
    con = con_for(dbpath)
    hetzner.init(con)
    client = FakeProviderClient()
    note = sweep_cli.refresh_provider(con, datetime.now(timezone.utc), lambda token: client)
    con.close()
    assert note == ""
    assert client.calls == 0


def test_a_token_and_no_snapshot_fetches_one(dbpath):
    from app import hetzner
    con = con_for(dbpath)
    hetzner.init(con)
    hetzner.add_token(con, "tok-" + "x" * 20, 1)
    client = FakeProviderClient()
    note = sweep_cli.refresh_provider(con, datetime.now(timezone.utc), lambda token: client)
    assert client.calls == 1
    assert "refreshed" in note
    assert hetzner.latest_snapshot(con) is not None
    con.close()


def test_a_fresh_snapshot_is_left_alone(dbpath):
    from app import hetzner
    con = con_for(dbpath)
    hetzner.init(con)
    hetzner.add_token(con, "tok-" + "x" * 20, 1)
    now = datetime.now(timezone.utc)
    hetzner.store_snapshot(con, hetzner.Snapshot(
        fetched_at=now.isoformat(), servers=(), firewalls=()))
    client = FakeProviderClient()
    assert sweep_cli.refresh_provider(con, now, lambda token: client) == ""
    assert client.calls == 0
    con.close()


def test_the_note_says_what_the_provider_said_is_left(dbpath):
    """A fleet big enough for the hourly request limit to matter says so before
    it bites."""
    from app import hetzner
    con = con_for(dbpath)
    hetzner.init(con)
    hetzner.add_token(con, "tok-" + "x" * 20, 1)
    note = sweep_cli.refresh_provider(con, datetime.now(timezone.utc),
                                      lambda token: FakeProviderClient(remaining=42))
    con.close()
    assert "42 requests left" in note


def test_a_provider_failure_does_not_stop_the_sweep(dbpath, sent, monkeypatch):
    """The rule that matters most here. A provider that timed out is not a
    provider that changed its mind, and the alerting this timer exists for
    must not stop because an API did."""
    from app import hetzner
    con = con_for(dbpath)
    hetzner.init(con)
    hetzner.add_token(con, "tok-" + "x" * 20, 1)
    con.close()
    monkeypatch.setattr(sweep_cli.hetzner, "client_for",
                        lambda token, opener=None: FakeProviderClient(
                            fail=hetzner.ProviderError("unreachable")))
    a_change_is_due(dbpath)
    assert sweep_cli.main([]) == 0
    assert len(sent) == 1, "a provider failure stopped the mail going out"


def test_a_provider_failure_keeps_the_snapshot_it_had(dbpath):
    from app import hetzner
    con = con_for(dbpath)
    hetzner.init(con)
    hetzner.add_token(con, "tok-" + "x" * 20, 1)
    old = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
    hetzner.store_snapshot(con, hetzner.Snapshot(
        fetched_at=old, servers=({"id": 1},), firewalls=()))
    note = sweep_cli.refresh_provider(
        con, datetime.now(timezone.utc),
        lambda token: FakeProviderClient(fail=hetzner.ProviderError("unreachable")))
    kept = hetzner.latest_snapshot(con)
    con.close()
    assert "not refreshed" in note
    assert kept.fetched_at == old, "a failed fetch replaced a good snapshot"


def test_the_failure_note_carries_the_typed_kind(dbpath):
    """SI-8's posture, and the class is what enforces it rather than this call
    site: `ProviderError` takes a kind as its only message and holds no
    provider text at all, so `str(exc)` is the kind. What is asserted here is
    that the note prints that kind rather than swallowing it, which is the half
    this function is responsible for."""
    from app import hetzner
    con = con_for(dbpath)
    hetzner.init(con)
    hetzner.add_token(con, "tok-" + "x" * 20, 1)
    note = sweep_cli.refresh_provider(
        con, datetime.now(timezone.utc),
        lambda token: FakeProviderClient(fail=hetzner.ProviderError("rate_limited")))
    con.close()
    assert "rate_limited" in note


def test_each_token_is_read_with_its_own_value_and_one_refusal_stops_no_other(dbpath):
    """One token per project since 2026-09-27 (docs/RECORD.md 4.206). Each is
    read on the same tick with its own value and its read stored under its
    own id, and a refused one leaves its neighbour's read alone."""
    from app import hetzner
    con = con_for(dbpath)
    hetzner.init(con)
    good, _ = hetzner.add_token(con, "good-" + "x" * 20, 3)
    bad, _ = hetzner.add_token(con, "bad-" + "y" * 20, 3)
    seen = []

    def factory(token):
        seen.append(token)
        if token.startswith("bad-"):
            return FakeProviderClient(fail=hetzner.ProviderError("unauthorized", status=401))
        return FakeProviderClient()

    note = sweep_cli.refresh_provider(con, datetime.now(timezone.utc), factory)
    assert seen == ["good-" + "x" * 20, "bad-" + "y" * 20]
    assert f"workspace 3 token {good}: provider snapshot refreshed" in note
    assert f"workspace 3 token {bad}: provider not refreshed: unauthorized" in note
    assert hetzner.latest_snapshot(con, workspace_id=3, token_id=good) is not None
    assert hetzner.latest_snapshot(con, workspace_id=3, token_id=bad) is None
    assert hetzner.latest_fetch(con, workspace_id=3, token_id=bad)["error_status"] == 401
    assert hetzner.latest_fetch(con, workspace_id=3, token_id=good)["error_kind"] is None
    # and the next tick asks again only for the token with nothing fresh
    seen.clear()
    sweep_cli.refresh_provider(con, datetime.now(timezone.utc), factory)
    assert seen == ["bad-" + "y" * 20]
    con.close()


# ----------------------------------------------- the channels that are not mail
#
# `tests/test_senders.py` proves what each channel puts on the wire. These prove
# the sweep reaches them at all, which is the half that would fail silently: a
# row an operator created, a delivery loop that never looks at its type, and an
# alert that is recorded and delivered nowhere.


@pytest.fixture()
def delivered(monkeypatch):
    """Every (url, body) the run would put on the wire, whatever the channel.

    Separate from `posted` above because that one's stand-in takes the webhook's
    exact arguments, and Telegram passes two more (`app/senders.py` reads its
    answer's body). A stand-in narrower than the real signature would fail on
    the channel this fixture exists to cover.
    """
    out = []

    def fake_send(payload, config=None, **kwargs):
        out.append((config.url if config else "", payload))
        return True, "posted"

    monkeypatch.setattr(sweep_cli.webhook, "send", fake_send)
    return out


def a_typed_channel(path, channel_type, label, env_name, extra=""):
    con = con_for(path)
    from app import channels
    channels.init(con)
    channel = channels.add(con, channel_type, label, env_name,
                           destination_extra=extra, now=ADDED)
    con.close()
    return channel


def test_a_slack_row_is_delivered_to(dbpath, sent, delivered, monkeypatch):
    monkeypatch.setenv("WHICHPORTS_SLACK_URL", "https://hooks.slack.com/services/T/B/X")
    a_change_is_due(dbpath)
    a_typed_channel(dbpath, "slack", "ops slack", "WHICHPORTS_SLACK_URL")
    assert sweep_cli.main([]) == 0
    assert len(delivered) == 1
    url, body = delivered[0]
    assert url == "https://hooks.slack.com/services/T/B/X"
    assert "text" in body, "slack got the webhook's typed document, not a message"


def test_two_different_channel_types_both_get_the_change(dbpath, sent, delivered,
                                                         monkeypatch):
    """One alert, two destinations, two deliveries. The mail is separate again
    and is not counted here."""
    monkeypatch.setenv("WHICHPORTS_SLACK_URL", "https://hooks.slack.com/services/T/B/X")
    monkeypatch.setenv("WHICHPORTS_TELEGRAM_TOKEN", "123:AA-nEvErIsSuEd")
    a_change_is_due(dbpath)
    a_typed_channel(dbpath, "slack", "ops slack", "WHICHPORTS_SLACK_URL")
    a_typed_channel(dbpath, "telegram", "ops tg", "WHICHPORTS_TELEGRAM_TOKEN",
                    extra="-100123")
    assert sweep_cli.main([]) == 0
    assert len(delivered) == 2
    kinds = {"text" in body for _, body in delivered}
    assert kinds == {True}, "one of the two got the wrong body shape"


def test_two_telegram_chats_behind_one_token_are_two_deliveries(dbpath, sent,
                                                                delivered,
                                                                monkeypatch):
    """The trap `docs/RECORD.md` 4.87 records, one level in. Keyed on the token
    alone, the first chat's delivery would mark the alert done and the second
    chat would never hear about it."""
    monkeypatch.setenv("WHICHPORTS_TELEGRAM_TOKEN", "123:AA-nEvErIsSuEd")
    a_change_is_due(dbpath)
    a_typed_channel(dbpath, "telegram", "ops one", "WHICHPORTS_TELEGRAM_TOKEN",
                    extra="-100111")
    a_typed_channel(dbpath, "telegram", "ops two", "WHICHPORTS_TELEGRAM_TOKEN",
                    extra="-100222")
    assert sweep_cli.main([]) == 0
    assert len(delivered) == 2
    chats = sorted(body["chat_id"] for _, body in delivered)
    assert chats == ["-100111", "-100222"]


def test_a_slack_row_ends_the_environment_fallback(dbpath, sent, delivered,
                                                   hooked, monkeypatch, capsys):
    """The fallback ends when a row of any sending type exists, not only a
    webhook one. Otherwise a box configured entirely through Slack rows would
    keep posting to a variable nobody pointed at."""
    monkeypatch.setenv("WHICHPORTS_SLACK_URL", "https://hooks.slack.com/services/T/B/X")
    a_change_is_due(dbpath)
    a_typed_channel(dbpath, "slack", "ops slack", "WHICHPORTS_SLACK_URL")
    assert sweep_cli.main([]) == 0
    assert "no channel rows" not in capsys.readouterr().out
    assert len(delivered) == 1


def test_a_row_whose_variable_is_unset_does_not_reopen_the_fallback(dbpath, sent,
                                                                    delivered,
                                                                    hooked,
                                                                    monkeypatch):
    """A configured channel that cannot deliver is an answer, not a reason to
    reach for a variable nobody named."""
    monkeypatch.delenv("WHICHPORTS_SLACK_URL", raising=False)
    a_change_is_due(dbpath)
    a_typed_channel(dbpath, "slack", "ops slack", "WHICHPORTS_SLACK_URL")
    assert sweep_cli.main([]) == 0
    assert delivered == []


def test_a_channel_only_takes_the_kinds_it_chose(dbpath, sent, delivered, monkeypatch):
    """The whole point of the choice: a chat channel a team watches all day and
    a mailbox one person reads at night do not want the same traffic."""
    monkeypatch.setenv("WHICHPORTS_SLACK_URL", "https://hooks.slack.com/services/T/B/X")
    a_change_is_due(dbpath)
    a_typed_channel(dbpath, "slack", "silence only", "WHICHPORTS_SLACK_URL")
    con = con_for(dbpath)
    from app import channels
    channels.set_subscriptions(con, "silence only", ["silent"])
    con.close()
    assert sweep_cli.main([]) == 0
    assert delivered == [], "a finding reached a channel subscribed to silences"


def test_an_unsubscribed_alert_is_not_asked_about_again(dbpath, sent, delivered,
                                                        monkeypatch):
    """Marked delivered rather than skipped. Left pending it would be
    reconsidered on every sweep for ever, which is a queue that never drains."""
    monkeypatch.setenv("WHICHPORTS_SLACK_URL", "https://hooks.slack.com/services/T/B/X")
    a_change_is_due(dbpath)
    a_typed_channel(dbpath, "slack", "silence only", "WHICHPORTS_SLACK_URL")
    con = con_for(dbpath)
    from app import alerts, channels
    channels.set_subscriptions(con, "silence only", ["silent"])
    con.close()
    sweep_cli.main([])
    con = con_for(dbpath)
    key = alerts.channel_key("slack", "WHICHPORTS_SLACK_URL")
    outstanding = alerts.pending_for_channel(con, key)
    con.close()
    assert outstanding == [], "the alert is still pending against a channel that refused it"


def test_a_channel_that_chose_the_kind_still_gets_it(dbpath, sent, delivered,
                                                     monkeypatch):
    """The other direction, so the test above cannot pass by delivering
    nothing at all."""
    monkeypatch.setenv("WHICHPORTS_SLACK_URL", "https://hooks.slack.com/services/T/B/X")
    a_change_is_due(dbpath)
    a_typed_channel(dbpath, "slack", "findings", "WHICHPORTS_SLACK_URL")
    con = con_for(dbpath)
    from app import channels
    channels.set_subscriptions(con, "findings", ["finding changed"])
    con.close()
    assert sweep_cli.main([]) == 0
    assert len(delivered) == 1


def test_two_channels_can_want_different_things(dbpath, sent, delivered, monkeypatch):
    monkeypatch.setenv("WHICHPORTS_SLACK_URL", "https://hooks.slack.com/services/T/B/X")
    monkeypatch.setenv("WHICHPORTS_DISCORD_URL", "https://discord.com/api/webhooks/1/x")
    a_change_is_due(dbpath)
    a_typed_channel(dbpath, "slack", "findings", "WHICHPORTS_SLACK_URL")
    a_typed_channel(dbpath, "discord", "silence only", "WHICHPORTS_DISCORD_URL")
    con = con_for(dbpath)
    from app import channels
    channels.set_subscriptions(con, "findings", ["finding changed"])
    channels.set_subscriptions(con, "silence only", ["silent"])
    con.close()
    assert sweep_cli.main([]) == 0
    assert len(delivered) == 1
    assert "hooks.slack.com" in delivered[0][0]


# ----------------------------------------------- email as a channel row

@pytest.fixture()
def mailed(monkeypatch):
    """Every (recipient, subject) the run would hand to a relay."""
    out = []

    def fake_send(subject, body, config=None, html=""):
        out.append((config.to if config else "", subject))
        return True, "sent"

    monkeypatch.setattr(sweep_cli.notify, "send", fake_send)
    return out


def an_email_channel(path, label, address, enabled=True, workspace_id=1):
    con = con_for(path)
    from app import channels
    channels.init(con)
    channel = channels.add(con, channels.TYPE_EMAIL, label, "",
                           destination=address, workspace_id=workspace_id, now=ADDED)
    if not enabled:
        channels.set_enabled(con, label, False)
    con.close()
    return channel


def test_with_no_email_rows_the_environment_recipient_is_used(dbpath, mailed,
                                                              posted, monkeypatch):
    """The box today. Nothing about its arrangement changes until a row
    exists."""
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", "sysadmin@example.org")
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    assert sweep_cli.main([]) == 0
    assert [to for to, _ in mailed] == ["sysadmin@example.org"]


def test_one_email_row_takes_over_from_the_environment(dbpath, mailed, posted,
                                                       monkeypatch):
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", "sysadmin@example.org")
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    an_email_channel(dbpath, "ops inbox", "ops@example.com")
    assert sweep_cli.main([]) == 0
    assert [to for to, _ in mailed] == ["ops@example.com"]


def test_two_email_rows_are_two_recipients(dbpath, mailed, posted, monkeypatch):
    """The thing the environment alone could never express."""
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    an_email_channel(dbpath, "ops inbox", "ops@example.com")
    an_email_channel(dbpath, "night rota", "night@example.com")
    assert sweep_cli.main([]) == 0
    assert sorted(to for to, _ in mailed) == ["night@example.com", "ops@example.com"]


def test_a_second_sweep_does_not_mail_the_same_alert_again(dbpath, mailed,
                                                           posted, monkeypatch):
    """Per recipient retry is alert_deliveries, so an alert one address already
    took is not sent to it twice."""
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    an_email_channel(dbpath, "ops inbox", "ops@example.com")
    sweep_cli.main([])
    before = len(mailed)
    sweep_cli.main([])
    assert len(mailed) == before, "the same alert was mailed twice"


def test_an_email_row_switched_off_does_not_reopen_the_environment(dbpath, mailed,
                                                                   posted,
                                                                   monkeypatch):
    """A configured channel that cannot deliver is an answer, not a reason to
    reach for a recipient nobody named."""
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", "sysadmin@example.org")
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    an_email_channel(dbpath, "ops inbox", "ops@example.com", enabled=False)
    assert sweep_cli.main([]) == 0
    assert mailed == []


def test_an_email_row_only_takes_the_kinds_it_chose(dbpath, mailed, posted,
                                                    monkeypatch):
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    an_email_channel(dbpath, "silence only", "ops@example.com")
    con = con_for(dbpath)
    from app import channels
    channels.set_subscriptions(con, "silence only", ["silent"])
    con.close()
    assert sweep_cli.main([]) == 0
    assert mailed == [], "a finding reached a mailbox subscribed to silences"


def test_mail_still_stamps_notified_at(dbpath, mailed, posted, monkeypatch):
    """RECORD 4.83 decided notified_at means a relay accepted the message and
    two screens read it. Moving mail onto rows must not make them say 'not
    mailed' about an alert that was mailed."""
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    an_email_channel(dbpath, "ops inbox", "ops@example.com")
    sweep_cli.main([])
    con = con_for(dbpath)
    stamped = con.execute(
        "SELECT COUNT(*) FROM alerts WHERE notified_at IS NOT NULL").fetchone()[0]
    con.close()
    assert stamped >= 1


def test_the_recipient_is_not_the_delivery_key(dbpath, mailed, posted, monkeypatch):
    """An address is not a credential, but it is a person, and a key is read off
    a screen. key_for_channel digests a stored destination, so it is a digest
    here too."""
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    an_email_channel(dbpath, "ops inbox", "ops@example.com")
    sweep_cli.main([])
    con = con_for(dbpath)
    keys = [r[0] for r in con.execute("SELECT DISTINCT channel FROM alert_deliveries")]
    con.close()
    assert keys, "nothing was recorded"
    for key in keys:
        assert "ops@example.com" not in key


def test_one_recipient_failing_does_not_stop_the_other_being_retried(dbpath,
                                                                     posted,
                                                                     monkeypatch):
    """**The bug the first version of this had.** It stamped notified_at on the
    first success and read its queue from pending_notifications, which filters
    on notified_at IS NULL. So the moment one address accepted, the alert left
    the mail queue and the address whose send had failed was never retried.

    `test_a_second_sweep_does_not_mail_the_same_alert_again` did not catch it,
    because a second sweep with nothing outstanding passes either way. This one
    fails the alert for exactly one recipient and then lets it succeed.
    """
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    an_email_channel(dbpath, "good one", "good@example.com")
    an_email_channel(dbpath, "flaky one", "flaky@example.com")

    attempts = []
    refuse = {"flaky@example.com"}

    def fake_send(subject, body, config=None, html=""):
        to = config.to if config else ""
        attempts.append(to)
        if to in refuse:
            return False, "the relay refused"
        return True, "sent"

    monkeypatch.setattr(sweep_cli.notify, "send", fake_send)

    sweep_cli.main([])
    assert sorted(attempts) == ["flaky@example.com", "good@example.com"]

    # The flaky one comes good. The alert must still be waiting for it, and the
    # one that already accepted must not be mailed again.
    refuse.clear()
    attempts.clear()
    sweep_cli.main([])
    assert attempts == ["flaky@example.com"], attempts


def test_a_recipient_that_keeps_failing_keeps_being_retried(dbpath, posted,
                                                            monkeypatch):
    """Nothing is stamped unless the relay accepted it, which is the rule the
    environment path has always followed."""
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    an_email_channel(dbpath, "dead one", "dead@example.com")

    attempts = []

    def fake_send(subject, body, config=None, html=""):
        attempts.append(config.to if config else "")
        return False, "the relay refused"

    monkeypatch.setattr(sweep_cli.notify, "send", fake_send)
    sweep_cli.main([])
    sweep_cli.main([])
    assert attempts == ["dead@example.com", "dead@example.com"]


# ------------------------------------------- a channel is one workspace's
#
# A row belongs to a workspace since 2026-08-29 (tests/test_channels.py says
# why), and the delivery loops respect it: a workspace's channel is only ever
# asked about that workspace's servers. The synthetic environment-only row is
# the operator's own arrangement and keeps watching the whole fleet.

def a_workspace_channel(path, workspace_id, label="ops",
                        env_name="WHICHPORTS_WEBHOOK_URL"):
    con = con_for(path)
    from app import channels
    channels.init(con)
    channel = channels.add(con, channels.TYPE_WEBHOOK, label, env_name,
                           workspace_id=workspace_id, now=ADDED)
    con.close()
    return channel


def move_host_to_workspace(path, host_name, workspace_id):
    con = con_for(path)
    con.execute("INSERT OR IGNORE INTO workspaces (id, name, created_at)"
                " VALUES (?, ?, ?)",
                (workspace_id, f"ws{workspace_id}", "2026-08-29T12:00:00+00:00"))
    con.execute("UPDATE hosts SET workspace_id = ? WHERE name = ?",
                (workspace_id, host_name))
    con.commit()
    con.close()


def test_another_workspaces_channel_does_not_take_the_alert(dbpath, sent,
                                                            posted, hooked):
    """The leak, pointed at delivery: workspace 2's webhook must never be
    handed workspace 1's finding."""
    a_change_is_due(dbpath)                      # host "one", workspace 1
    a_workspace_channel(dbpath, workspace_id=2)  # somebody else's channel
    assert sweep_cli.main([]) == 0
    assert posted == []


def test_the_workspaces_own_channel_takes_it(dbpath, sent, posted, hooked):
    a_change_is_due(dbpath)
    move_host_to_workspace(dbpath, "one", 2)
    a_workspace_channel(dbpath, workspace_id=2)
    assert sweep_cli.main([]) == 0
    assert len(posted) == 1


def test_the_environment_fallback_still_watches_every_workspace(dbpath, sent,
                                                                posted, hooked):
    """No rows at all, so the operator's environment-only arrangement holds,
    and it is fleet-wide on purpose: it is the operator's own channel and a
    workspace 2 finding still reaches it."""
    a_change_is_due(dbpath)
    move_host_to_workspace(dbpath, "one", 2)
    assert sweep_cli.main([]) == 0
    assert len(posted) == 1


# ------------------------------------- mail is decided one workspace at a time
#
# Read off production on 2026-09-20: workspace 1 held two email rows, workspace
# 3 held none, and the sweep decided "rows or the environment" once for the
# whole fleet. So workspace 1's rows switched the environment off for
# everybody, and the first outside server could mail nobody. The owner the same
# day: the environment's recipient is the operator's own and never receives
# another workspace's alert.

def test_one_workspaces_email_row_does_not_take_anothers_mail(dbpath, mailed,
                                                              posted, monkeypatch):
    """Workspace 1 has a row. The host is in workspace 3, which has its own.
    Only workspace 3's address is mailed."""
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", "sysadmin@example.org")
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    move_host_to_workspace(dbpath, "one", 3)
    an_email_channel(dbpath, "operator", "ops@example.com", workspace_id=1)
    an_email_channel(dbpath, "tester", "tester@example.org", workspace_id=3)
    assert sweep_cli.main([]) == 0
    assert [to for to, _ in mailed] == ["tester@example.org"]


def test_the_environment_recipient_never_gets_another_workspaces_alert(
        dbpath, mailed, posted, monkeypatch):
    """No email row anywhere, and the host is in workspace 3. The address in
    the box's environment is the operator's, so it is not mailed."""
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", "sysadmin@example.org")
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    move_host_to_workspace(dbpath, "one", 3)
    assert sweep_cli.main([]) == 0
    assert mailed == []


def test_another_workspaces_row_leaves_the_operators_environment_alone(
        dbpath, mailed, posted, monkeypatch):
    """The mirror of the production fault: a tester adding an email row must
    not switch off the operator's own mail."""
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", "sysadmin@example.org")
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)                       # host "one", workspace 1
    an_email_channel(dbpath, "tester", "tester@example.org", workspace_id=3)
    assert sweep_cli.main([]) == 0
    assert [to for to, _ in mailed] == ["sysadmin@example.org"]


def a_host_went_silent(path):
    con = con_for(path)
    host_id, _ = store.add_host(con, "one")
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                ("2026-01-01T00:00:00+00:00", host_id))
    con.commit()
    con.close()


def test_a_silence_alert_follows_the_same_rule(dbpath, mailed, posted,
                                               monkeypatch):
    """The dead-man alert goes through a different queue than a finding, so
    it is held separately: workspace 3's silent host never mails the
    environment's recipient."""
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", "sysadmin@example.org")
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_host_went_silent(dbpath)
    move_host_to_workspace(dbpath, "one", 3)
    assert sweep_cli.main([]) == 0
    assert mailed == []


def test_the_operators_own_silent_host_still_mails_the_environment(
        dbpath, mailed, posted, monkeypatch):
    """The control for the test above: the same silent host left in workspace
    1 does mail, so the test above is not passing on a host that never
    alerts."""
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", "sysadmin@example.org")
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_host_went_silent(dbpath)
    assert sweep_cli.main([]) == 0
    assert [to for to, _ in mailed] == ["sysadmin@example.org"]



# ---------------------------------- a destination hears what is raised after it
#
# Decided on 26 October 2026 after the second big test's E10a: a Webhook added
# during two open silences was sent both at the next sweep, with every open
# finding alert of three servers and a notice of the day before. A destination
# hears what is raised after it was added and nothing raised before. Its
# `created_at` is when it was added.

def a_channel_at(path, when, label="ops", env_name="WHICHPORTS_WEBHOOK_URL"):
    con = con_for(path)
    from app import channels
    channels.init(con)
    channel = channels.add(con, channels.TYPE_WEBHOOK, label, env_name, now=when)
    con.close()
    return channel


def test_a_destination_added_after_a_change_was_raised_is_not_told_it(dbpath, sent, posted, hooked):
    a_change_is_due(dbpath)
    a_channel_at(dbpath, NOW + DEBOUNCE + timedelta(minutes=1))
    assert sweep_cli.main([]) == 0
    assert posted == []


def test_a_destination_there_when_the_change_was_raised_is_told_it(dbpath, sent, posted, hooked):
    a_channel_at(dbpath, NOW - timedelta(days=1))
    a_change_is_due(dbpath)
    assert sweep_cli.main([]) == 0
    assert len(posted) == 1 and posted[0]["kind"] == "finding changed"


def test_a_destination_added_during_a_silence_is_not_told_that_silence(
        dbpath, sent, posted, hooked, monkeypatch):
    monkeypatch.setenv("WHICHPORTS_WEBHOOK_URL_SEC", "https://other.example/h")
    wall = datetime.now(timezone.utc)
    a_channel_at(dbpath, wall - timedelta(days=3), label="ops")
    con = con_for(dbpath)
    host_id, _ = store.add_host(con, "one")
    store.insert_report(con, host_id, 1, 1, json.dumps(document([])))
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                ((wall - timedelta(days=2)).isoformat(), host_id))
    con.commit()
    con.close()
    assert sweep_cli.main([]) == 0
    assert len(posted) == 1
    a_channel_at(dbpath, datetime.now(timezone.utc), label="security",
                 env_name="WHICHPORTS_WEBHOOK_URL_SEC")
    assert sweep_cli.main([]) == 0
    assert len(posted) == 1
