"""The Prometheus endpoint: the sensor half of the product (RECORD 4.1)."""

import json

import pytest
from fastapi.testclient import TestClient

from app import db, ingest, store
from operator_gate import gate



@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "m.db"))
    return TestClient(ingest.app)


def add(client, name):
    return client.post("/api/admin/hosts", content=json.dumps({"name": name}),
                       headers=gate()).json()["credential"]


def report(client, credential, hostname="box", **doc):
    body = {"schema_version": 1, "collected_at_unix": 1, "hostname": hostname}
    body.update(doc)
    return client.post("/api/v1/reports", content=json.dumps(body),
                       headers={"Authorization": f"Bearer {credential}"})


def scrape(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    return resp.text


def test_scrape_is_valid_exposition_with_help_and_type(client):
    body = scrape(client)
    assert "# HELP whichports_up" in body
    assert "# TYPE whichports_up gauge" in body
    assert "whichports_up 1" in body
    # every emitted family declares itself
    families = {line.split()[0] for line in body.splitlines()
                if line and not line.startswith("#")}
    for family in families:
        base = family.split("{")[0]
        assert f"# HELP {base} " in body, f"{base} has no HELP line"


def test_host_series_carry_the_documents_facts(client):
    credential = add(client, "box")
    report(client, credential,
           sockets={"status": "collected",
                    "listening": [{"port": 22}, {"port": 80}]},
           containers={"status": "collected",
                       "podman": [{"id": "a", "ports": [{"host_port": 8096}]}]},
           nftables={"status": "collected"},
           ufw={"status": "not_present"})
    body = scrape(client)
    assert 'whichports_host_listening_sockets{host="box"} 2' in body
    assert 'whichports_host_published_ports{host="box"} 1' in body
    assert 'whichports_host_sections_collected{host="box"} 3' in body
    assert 'whichports_host_sections_total{host="box"} 9' in body
    assert 'whichports_host_documents_total{host="box"} 1' in body
    assert 'whichports_host_last_report_age_seconds{host="box"}' in body


def test_no_metric_claims_reachability(client):
    """The prober does not exist. A metric implying it would be exactly the
    error PRODUCT.md 4b exists to prevent."""
    credential = add(client, "box")
    report(client, credential)
    body = scrape(client).lower()
    for forbidden in ("reachable", "reachability", "open_port", "exposed"):
        assert forbidden not in body


def test_fleet_state_counts(client):
    add(client, "never")
    reporting = add(client, "fresh")
    report(client, reporting)
    paused = add(client, "sleepy")
    report(client, paused)
    client.post("/api/admin/hosts/sleepy/pause",
                content=json.dumps({"paused": True}), headers=gate())
    revoked = add(client, "gone")
    report(client, revoked)
    client.post("/api/admin/hosts/gone/revoke", headers=gate())
    body = scrape(client)
    assert 'whichports_hosts{state="reporting"} 1' in body
    assert 'whichports_hosts{state="never_reported"} 1' in body
    assert 'whichports_hosts{state="paused"} 1' in body
    assert 'whichports_hosts{state="revoked"} 1' in body
    assert 'whichports_host_paused{host="sleepy"} 1' in body


def test_never_reported_host_emits_no_age(client):
    add(client, "quiet")
    body = scrape(client)
    assert 'whichports_host_documents_total{host="quiet"} 0' in body
    assert 'whichports_host_last_report_age_seconds{host="quiet"}' not in body


# ------------------------------------------------- the alerting has a sensor

def open_alert(client, host, raised="2026-08-15T12:00:00+00:00", notified=None,
               kind="silent"):
    """Write an alert straight into the database. The sweep is tested in
    test_alerts.py, and what is under test here is only whether a scrape can
    see one."""
    from app import alerts
    con = db.connect()
    db.init(con)
    alerts.init(con)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (host,)).fetchone()["id"]
    con.execute("INSERT INTO alerts (host_id, kind, detail, raised_at, notified_at)"
                " VALUES (?, ?, ?, ?, ?)", (host_id, kind, "detail", raised, notified))
    con.commit()
    con.close()


def test_an_open_alert_is_visible_to_a_scrape(client):
    """Two silence alerts sat open on production for a day and nothing on any
    wallboard could see them, because the alerting subsystem had no metric at
    all. The dead-man switch exists so a quiet failure is loud, and it was
    itself the quiet one."""
    add(client, "box1")
    open_alert(client, "box1")
    body = scrape(client)
    assert 'whichports_alerts_open{kind="silent"} 1' in body


def test_a_resolved_alert_is_not_open(client):
    add(client, "box1")
    open_alert(client, "box1")
    con = db.connect()
    con.execute("UPDATE alerts SET resolved_at = '2026-08-15T13:00:00+00:00'")
    con.commit()
    con.close()
    assert 'whichports_alerts_open{kind="silent"} 0' in scrape(client)


def test_an_alert_that_was_never_delivered_is_counted_separately(client):
    """The metric that would have shown the SMTP outage. While the relay was
    refusing the sender, every alert was recorded and none was delivered, and
    the only way to know was to read the journal on the box."""
    add(client, "box1")
    add(client, "box2")
    open_alert(client, "box1", notified="2026-08-15T12:01:00+00:00")
    open_alert(client, "box2", notified=None)
    body = scrape(client)
    assert 'whichports_alerts_open{kind="silent"} 2' in body
    assert "whichports_alerts_undelivered 1" in body


def test_the_alert_series_exist_even_when_there_are_none(client):
    """A gauge that is absent when the count is zero is a gauge nobody can
    alert on, because the query returns no data instead of returning 0. The
    kinds this control plane can raise are known ahead of time, so all of them
    are emitted."""
    add(client, "box1")
    body = scrape(client)
    assert 'whichports_alerts_open{kind="silent"} 0' in body
    assert "whichports_alerts_undelivered 0" in body
    assert "# TYPE whichports_alerts_open gauge" in body


def test_no_alert_metric_claims_reachability(client):
    """The rule this file already enforces for the host series, extended to the
    new ones. Nothing here has measured anything from outside."""
    add(client, "box1")
    open_alert(client, "box1")
    body = scrape(client).lower()
    for word in ("reachable", "unreachable", "open_port", "exposed", "secure"):
        assert word not in body, f"a metric name or help text says {word}"


def test_an_alert_kind_this_build_does_not_know_is_still_counted(client):
    """A row written by a newer build, or by hand. Dropping it would make the
    scrape quietly disagree with the database."""
    add(client, "box1")
    open_alert(client, "box1", kind="something_newer")
    assert 'whichports_alerts_open{kind="something_newer"} 1' in scrape(client)


def test_label_values_are_escaped():
    assert '\\"' in ingest.metrics.escape_label('a"b')
    assert "\\\\" in ingest.metrics.escape_label("a\\b")
    assert "\n" not in ingest.metrics.escape_label("a\nb")


def test_empty_fleet_still_scrapes(client):
    body = scrape(client)
    assert "whichports_up 1" in body
    assert 'whichports_hosts{state="reporting"} 0' in body


# ------------------------------------- the measurement reaches the wallboard

def store_probe_run(client, host, results, started="2026-08-15T12:00:00+00:00",
                    vantage="vantage-1"):
    """Write a probe run the way app/prober.py's schema holds one. The engine
    is tested in test_prober.py, and what is under test here is only whether a
    scrape can see what it measured."""
    from app import prober
    con = db.connect()
    db.init(con)
    prober.init(con)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (host,)).fetchone()["id"]
    cur = con.execute("INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
                      " VALUES (?, ?, ?, ?)", (host_id, vantage, started, started))
    for target, family, port, state, reason in results:
        con.execute("INSERT INTO probe_results (run_id, target, family, port, state,"
                    " reason, measured_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (cur.lastrowid, target, family, port, state, reason, started))
    con.commit()
    con.close()


def test_a_measured_result_is_counted_by_its_own_state_word(client):
    """The loop this module's docstring opened. It said nothing here may be
    called reachable until it is measured, because reachable is the prober's
    word alone. It was measured for the first time on 2026-08-16, so the
    counts are here, carrying the prober's own four state words rather than a
    fifth spelling invented for the wallboard.
    """
    add(client, "box1")
    report(client, add(client, "box2"))
    store_probe_run(client, "box1", [
        ("192.0.2.1", "v4", 22, "connect_succeeded", None),
        ("192.0.2.1", "v4", 80, "connect_succeeded", None),
        ("192.0.2.1", "v4", 53, "no_response", "timeout_expired"),
    ])
    body = scrape(client)
    assert 'whichports_probe_results{host="box1",family="v4",state="connect_succeeded"} 2' in body
    assert 'whichports_probe_results{host="box1",family="v4",state="no_response"} 1' in body


def test_no_metric_calls_a_measurement_reachable(client):
    """The writing rules and the accuracy rule. The prober measured whether a
    connect completed. Whether that means reachable is the reader's conclusion,
    and a metric named for it would be us drawing it for them."""
    add(client, "box1")
    store_probe_run(client, "box1", [("192.0.2.1", "v4", 22, "connect_succeeded", None)])
    body = scrape(client).lower()
    for word in ("reachable", "unreachable", "exposed", "open_port", "secure", "blocked"):
        assert word not in body, f"a metric name or help text says {word}"


def test_a_host_never_probed_emits_no_probe_series_rather_than_zero(client):
    """Zero measured results and a measurement of zero are different facts. A
    host nobody probed must not read as a host where nothing answered.

    The first version of this test passed against a build that emitted the zero
    series, because it created no probe run at all, so the probe tables did not
    exist and the scrape bailed out before it could reach the branch under
    test. It was passing for the wrong reason, which is RECORD 4.50's lesson.
    A second host is probed here so the tables exist and box1 is genuinely a
    host with no run of its own.
    """
    add(client, "box1")
    add(client, "other")
    store_probe_run(client, "other", [("192.0.2.9", "v4", 22, "connect_succeeded", None)])
    body = scrape(client)
    assert 'whichports_probe_results{host="other"' in body, "the fixture did not take"
    assert 'whichports_probe_results{host="box1"' not in body
    assert 'whichports_probe_last_run_age_seconds{host="box1"}' not in body


def test_the_age_of_the_measurement_is_published(client):
    """A reachability finding is only as good as its clock. A scrape that says
    what was measured without saying when invites somebody to act on a week
    old answer."""
    add(client, "box1")
    store_probe_run(client, "box1", [("192.0.2.1", "v4", 22, "connect_succeeded", None)],
                    started="2026-08-15T11:00:00+00:00")
    body = scrape(client)
    assert 'whichports_probe_last_run_age_seconds{host="box1"}' in body


def test_only_the_newest_run_is_counted(client):
    """Two runs against one host is the normal case on any cadence. Summing
    them would report a port twice and make a fleet look busier than it is."""
    add(client, "box1")
    store_probe_run(client, "box1", [("192.0.2.1", "v4", 22, "connect_succeeded", None)],
                    started="2026-08-15T10:00:00+00:00")
    store_probe_run(client, "box1", [("192.0.2.1", "v4", 22, "no_response", "timeout_expired")],
                    started="2026-08-15T12:00:00+00:00")
    body = scrape(client)
    assert 'state="no_response"} 1' in body
    assert 'state="connect_succeeded"' not in body, "an older run is still being counted"


def test_a_probe_state_this_build_does_not_know_is_still_counted(client):
    """Same rule the alert kinds follow: the scrape must not quietly disagree
    with the database."""
    add(client, "box1")
    store_probe_run(client, "box1", [("192.0.2.1", "v4", 22, "something_newer", None)])
    assert 'state="something_newer"} 1' in scrape(client)


def test_the_probe_tables_not_existing_is_not_a_failed_scrape(client):
    """A control plane where the prober has never been initialised still has
    to answer, or the metric that says we are up goes down with it."""
    add(client, "box1")
    body = scrape(client)
    assert "whichports_up 1" in body


# ============================================ the vantage registry, 2026-09-08


def register_vantage(name, enabled=True):
    from app import vantages
    con = db.connect()
    db.init(con)
    vantages.init(con)
    vantages.add(con, name, f"root@{name}", [f"185.199.110.{int(name[-1])}"])
    if not enabled:
        vantages.set_enabled(con, name, False)
    con.close()


def test_each_registered_vantage_says_whether_it_is_driven_and_how_old_its_last_pass_is(client):
    add(client, "box1")
    register_vantage("probe1")
    register_vantage("probe2", enabled=False)
    store_probe_run(client, "box1", [("192.0.2.1", "v4", 22, "connect_succeeded", None)],
                    started="2026-08-15T11:00:00+00:00", vantage="probe1")
    body = scrape(client)
    assert 'whichports_vantage_enabled{vantage="probe1"} 1' in body
    assert 'whichports_vantage_enabled{vantage="probe2"} 0' in body
    assert 'whichports_vantage_last_run_age_seconds{vantage="probe1"}' in body
    assert 'whichports_vantage_last_run_age_seconds{vantage="probe2"}' not in body, \
        "a vantage that never finished a pass has no age, not a zero"


def test_a_dead_second_vantage_shows_in_its_own_series_while_the_host_reads_fresh(client):
    """The host series answer for the newest run of any vantage, so they read
    fresh while probe2 has been silent for a day. The vantage series is the
    one that says so."""
    add(client, "box1")
    register_vantage("probe1")
    register_vantage("probe2")
    store_probe_run(client, "box1", [("192.0.2.1", "v4", 22, "connect_succeeded", None)],
                    started="2026-08-14T12:00:00+00:00", vantage="probe2")
    store_probe_run(client, "box1", [("192.0.2.1", "v4", 22, "connect_succeeded", None)],
                    started="2026-08-15T12:00:00+00:00", vantage="probe1")
    body = scrape(client)
    ages = {}
    for line in body.splitlines():
        if line.startswith("whichports_vantage_last_run_age_seconds"):
            name = line.split('vantage="')[1].split('"')[0]
            ages[name] = int(line.rsplit(" ", 1)[1])
    assert ages["probe2"] - ages["probe1"] == 24 * 3600


def test_no_registry_publishes_no_vantage_series_and_the_scrape_still_answers(client):
    add(client, "box1")
    body = scrape(client)
    assert "whichports_up 1" in body
    assert "whichports_vantage_" not in body.split("# HELP whichports_vantage_enabled")[0] \
        or "whichports_vantage_enabled{" not in body
