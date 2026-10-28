"""The dead-man sweep.

    python -m pytest tests/test_alerts.py

Every rule in app/alerts.py's docstring has a test here, and the two that
matter most are the ones that stop this feature becoming the thing everybody
filters into a folder: one alert per silence rather than one per sweep, and
our own outage never becoming their alert.

The self-outage guard is the one an earlier project of the author's learned
by shipping the bug (a redeploy fired one alert per server, every one
resolved a minute later). It is
reimplemented here rather than copied, so it is tested here from scratch.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app import alerts, db, store

NOW = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)
SILENT = timedelta(seconds=alerts.SILENT_AFTER_SECONDS)


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    alerts.init(connection)
    yield connection
    connection.close()


def add(con, name, last_report=None, created=None, paused=False, revoked=False):
    host_id, _ = store.add_host(con, name)
    con.execute("UPDATE hosts SET last_report_at = ?, created_at = ?, paused = ?,"
                " revoked_at = ? WHERE id = ?",
                (last_report.isoformat() if last_report else None,
                 (created or NOW - timedelta(days=1)).isoformat(),
                 1 if paused else 0,
                 NOW.isoformat() if revoked else None,
                 host_id))
    con.commit()
    return host_id


def open_rows(con):
    return con.execute("SELECT * FROM alerts WHERE resolved_at IS NULL").fetchall()


# ------------------------------------------------------------------ raising

def test_a_host_past_the_threshold_raises_once(con):
    add(con, "quiet", last_report=NOW - SILENT - timedelta(minutes=1))
    result = alerts.sweep(con, now=NOW)
    assert result["raised"] == ["quiet"]
    assert len(open_rows(con)) == 1


def test_a_host_inside_the_threshold_raises_nothing(con):
    add(con, "fresh", last_report=NOW - timedelta(minutes=5))
    result = alerts.sweep(con, now=NOW)
    assert result["raised"] == []
    assert open_rows(con) == []


def test_one_silence_is_one_alert_however_many_sweeps_run(con):
    """The thing that decides whether this feature survives contact with a
    real outage. Twelve sweeps an hour for a week is 2,016 sweeps."""
    add(con, "quiet", last_report=NOW - SILENT - timedelta(minutes=1))
    for minute in range(0, 60, 5):
        alerts.sweep(con, now=NOW + timedelta(minutes=minute))
    rows = con.execute("SELECT * FROM alerts").fetchall()
    assert len(rows) == 1


def test_the_detail_says_what_was_measured(con):
    add(con, "quiet", last_report=NOW - timedelta(minutes=90))
    alerts.sweep(con, now=NOW)
    detail = open_rows(con)[0]["detail"]
    assert "90 minutes" in detail
    assert "35 minute threshold" in detail


# ----------------------------------------------------------------- resolving

def test_a_host_that_comes_back_resolves(con):
    host_id = add(con, "quiet", last_report=NOW - SILENT - timedelta(minutes=1))
    alerts.sweep(con, now=NOW)
    assert len(open_rows(con)) == 1
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                (NOW.isoformat(), host_id))
    con.commit()
    result = alerts.sweep(con, now=NOW + timedelta(minutes=5))
    assert result["resolved"] == ["quiet"]
    assert open_rows(con) == []


def test_resolving_needs_a_real_report_not_a_hover_at_the_boundary(con):
    """One threshold for both directions makes a host at the edge raise and
    resolve on alternate sweeps, which is how an alert channel gets muted."""
    host_id = add(con, "edge", last_report=NOW - SILENT - timedelta(minutes=1))
    alerts.sweep(con, now=NOW)
    # Still older than the resolve bound, even though under the raise bound.
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                ((NOW - timedelta(seconds=alerts.ONLINE_WITHIN_SECONDS + 60)).isoformat(),
                 host_id))
    con.commit()
    alerts.sweep(con, now=NOW + timedelta(minutes=1))
    assert len(open_rows(con)) == 1, "an alert resolved without a recent report"


# -------------------------------------------------------------------- pause

def test_a_paused_host_never_raises(con):
    add(con, "maintenance", last_report=NOW - timedelta(days=3), paused=True)
    result = alerts.sweep(con, now=NOW)
    assert result["raised"] == []
    assert open_rows(con) == []


def test_pausing_clears_an_alert_that_was_already_open(con):
    """Pausing is the operator explaining the silence. Leaving a red row
    behind for something they have just accounted for is how a dashboard
    stops being read."""
    host_id = add(con, "box", last_report=NOW - SILENT - timedelta(minutes=1))
    alerts.sweep(con, now=NOW)
    assert len(open_rows(con)) == 1
    con.execute("UPDATE hosts SET paused = 1 WHERE id = ?", (host_id,))
    con.commit()
    result = alerts.sweep(con, now=NOW + timedelta(minutes=5))
    assert result["closed"] == ["box"], "a pause must not read as reporting again"
    assert result["resolved"] == []
    assert open_rows(con) == []


def test_a_paused_host_suppresses_only_silence(con):
    """PRODUCT.md 4c: a pause suppresses the silence alert, never a real
    finding. There is only one kind today, so this pins that the pause branch
    is keyed on the kind rather than clearing everything for the host."""
    host_id = add(con, "box", last_report=NOW - timedelta(days=1), paused=True)
    alerts.raise_alert(con, host_id, "some_other_kind", "a real finding", NOW)
    con.commit()
    alerts.sweep(con, now=NOW)
    kinds = [r["kind"] for r in open_rows(con)]
    assert kinds == ["some_other_kind"]


# ------------------------------------------------------------------ revoked

def test_a_revoked_host_is_not_monitored(con):
    add(con, "gone", last_report=NOW - timedelta(days=5), revoked=True)
    result = alerts.sweep(con, now=NOW)
    assert result["checked"] == 0
    assert open_rows(con) == []


def test_revoking_clears_an_alert_that_was_already_open(con):
    """Found by running the sweep against a real snapshot: five never-used
    host rows each raised, and revoking them skipped the hosts but left five
    open alerts behind with nothing that would ever close them."""
    host_id = add(con, "junk", last_report=NOW - timedelta(days=2))
    alerts.sweep(con, now=NOW)
    assert len(open_rows(con)) == 1
    con.execute("UPDATE hosts SET revoked_at = ? WHERE id = ?", (NOW.isoformat(), host_id))
    con.commit()
    result = alerts.sweep(con, now=NOW + timedelta(minutes=5))
    assert result["closed"] == ["junk"], "a revoke must not read as reporting again"
    assert result["resolved"] == []
    assert open_rows(con) == []


# ------------------------------------------------------- never reported yet

def test_a_new_host_is_measured_from_enrolment_not_from_never(con):
    """A host added a minute ago has not reported, and that is not an outage.
    Without this it would alert before anyone could run the installer."""
    add(con, "justadded", last_report=None, created=NOW - timedelta(minutes=2))
    result = alerts.sweep(con, now=NOW)
    assert result["raised"] == []


def test_a_host_that_never_reported_never_raises_the_silence_alert(con):
    """The rule that outranks the rest (the accuracy rule). The silence alert
    states that an agent stopped reporting. A row the add-server flow created
    and nobody ever installed never started, so raising it there states
    something nobody measured.

    Measured on the production database, copy taken 2026-08-16: nine host rows
    had never reported, seven were hand-revoked to shut this alert up (RECORD
    4.41 and 4.47) and two were still open and had already been mailed.
    """
    add(con, "neverran", last_report=None, created=NOW - timedelta(days=2))
    result = alerts.sweep(con, now=NOW)
    assert result["raised"] == []
    assert result["pending"] == ["neverran"]
    assert [row["kind"] for row in open_rows(con)] == []


def test_an_alert_already_raised_against_a_never_reported_host_is_retracted(con):
    """The two rows sitting open on production when this was written. Fixing
    the raise alone would leave them open for ever, because only a report they
    will never send resolves an alert."""
    host_id = add(con, "phantom", last_report=None, created=NOW - timedelta(days=2))
    alerts.raise_alert(con, host_id, alerts.KIND_SILENT, "raised by the old sweep", NOW)
    assert len(open_rows(con)) == 1
    result = alerts.sweep(con, now=NOW + timedelta(minutes=5))
    assert result["retracted"] == ["phantom"]
    assert result["resolved"] == [], "a retraction must not read as reporting again"
    assert open_rows(con) == []


def test_retracting_happens_once_and_not_on_every_sweep(con):
    """The de-duplication property the whole module turns on, checked on the
    new path too: twelve sweeps an hour must not print twelve retractions."""
    host_id = add(con, "phantom", last_report=None, created=NOW - timedelta(days=2))
    alerts.raise_alert(con, host_id, alerts.KIND_SILENT, "raised by the old sweep", NOW)
    first = alerts.sweep(con, now=NOW + timedelta(minutes=5))
    second = alerts.sweep(con, now=NOW + timedelta(minutes=10))
    assert first["retracted"] == ["phantom"]
    assert second["retracted"] == []


def test_a_host_that_reported_once_and_then_stopped_still_raises(con):
    """The boundary the other side of. This is the alert the feature exists
    for and the fix must not have muted it."""
    add(con, "died", last_report=NOW - SILENT - timedelta(minutes=1),
        created=NOW - timedelta(days=30))
    result = alerts.sweep(con, now=NOW)
    assert result["raised"] == ["died"]
    assert result["pending"] == []


def test_a_last_report_stamp_that_cannot_be_read_raises_nothing(con):
    """A host that has reported, whose freshness stamp is unreadable. The old
    code fell back to created_at and would have printed "no report for N
    minutes" with N measured from enrolment, a number nobody observed. It is
    named instead, so a fault in our own data is visible rather than dressed
    up as a fault on the host."""
    host_id = add(con, "garbled", last_report=NOW - timedelta(hours=3))
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?", ("not a date", host_id))
    con.commit()
    result = alerts.sweep(con, now=NOW)
    assert result["raised"] == []
    assert result["unreadable"] == ["garbled"]
    assert result["pending"] == [], "a stamp we cannot read is not the same as no stamp"


# -------------------------------------------------------- the self-outage guard

def test_our_own_outage_does_not_become_their_alert(con):
    """The bug the earlier project shipped: a redeploy makes every agent look
    silent at once. The gap since the last sweep is the tell."""
    add(con, "a", last_report=NOW - timedelta(hours=3))
    add(con, "b", last_report=NOW - timedelta(hours=3))
    # A normal sweep three hours ago, establishing the baseline.
    alerts.sweep(con, now=NOW - timedelta(hours=3))
    # Then nothing for three hours, because we were down.
    result = alerts.sweep(con, now=NOW)
    assert result["self_outage"] is True
    assert result["raised"] == []
    assert sorted(result["held"]) == ["a", "b"]
    assert open_rows(con) == []


def test_the_guard_delays_a_real_detection_and_does_not_cancel_it(con):
    """The property that makes the guard safe to have at all, swept at the
    cadence the timer actually uses. The first version of this failed here:
    it re-armed its own deadline on every sweep, which turned delay into
    never."""
    add(con, "reallydead", last_report=NOW - timedelta(hours=3))
    alerts.sweep(con, now=NOW - timedelta(hours=3))
    held = alerts.sweep(con, now=NOW)                  # our outage
    assert held["self_outage"] is True and held["raised"] == []
    # Five minute sweeps from here, as the unit does. Nothing raises until a
    # full silence window has passed with the control plane actually up.
    raised = []
    for minute in range(5, 45, 5):
        result = alerts.sweep(con, now=NOW + timedelta(minutes=minute))
        assert result["self_outage"] is False, "a normal gap read as an outage"
        raised.extend(result["raised"])
    assert raised == ["reallydead"], "the guard cancelled a real detection"


def test_the_guard_measures_from_recovery_not_from_the_last_report(con):
    """Right after recovery the host is inside the observed window even though
    its own report is hours old, so nothing raises yet."""
    add(con, "quiet", last_report=NOW - timedelta(hours=3))
    alerts.sweep(con, now=NOW - timedelta(hours=3))
    alerts.sweep(con, now=NOW)
    result = alerts.sweep(con, now=NOW + timedelta(minutes=30))
    assert result["raised"] == []
    assert result["held"] == ["quiet"]


def test_a_host_that_comes_back_during_the_grace_is_never_alerted_at_all(con):
    host_id = add(con, "recovered", last_report=NOW - timedelta(hours=3))
    alerts.sweep(con, now=NOW - timedelta(hours=3))
    alerts.sweep(con, now=NOW)
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                ((NOW + timedelta(minutes=10)).isoformat(), host_id))
    con.commit()
    result = alerts.sweep(con, now=NOW + timedelta(minutes=12))
    assert result["raised"] == []
    assert con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0


def test_a_first_ever_sweep_does_not_open_a_grace(con):
    """A fresh database has no baseline, and treating that as our outage would
    mute the first real alert on a new install."""
    add(con, "quiet", last_report=NOW - timedelta(hours=3))
    result = alerts.sweep(con, now=NOW)
    assert result["self_outage"] is False
    assert result["raised"] == ["quiet"]


def test_a_short_gap_between_sweeps_is_not_an_outage(con):
    add(con, "quiet", last_report=NOW - timedelta(hours=3))
    alerts.sweep(con, now=NOW - timedelta(minutes=5))
    result = alerts.sweep(con, now=NOW)
    assert result["self_outage"] is False


# ------------------------------------------------------------- notifications

def test_a_raised_alert_is_pending_until_it_is_stamped(con):
    add(con, "quiet", last_report=NOW - SILENT - timedelta(minutes=1))
    alerts.sweep(con, now=NOW)
    pending = alerts.pending_notifications(con)
    assert [row["host_name"] for row in pending] == ["quiet"]
    alerts.mark_notified(con, pending[0]["id"], NOW)
    assert alerts.pending_notifications(con) == []


def test_a_resolved_alert_is_never_delivered_late(con):
    """If it resolved before delivery got to it, mailing about it is noise."""
    host_id = add(con, "blip", last_report=NOW - SILENT - timedelta(minutes=1))
    alerts.sweep(con, now=NOW)
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                ((NOW + timedelta(minutes=4)).isoformat(), host_id))
    con.commit()
    alerts.sweep(con, now=NOW + timedelta(minutes=5))
    assert alerts.pending_notifications(con) == []


# ------------------------------------------------------------ hostile inputs

@pytest.mark.parametrize("stamp", ["", "not a date", "2026-13-45T99:99:99", None])
def test_an_unparseable_timestamp_does_not_take_the_sweep_down(con, stamp):
    host_id = add(con, "odd", last_report=NOW - timedelta(hours=3))
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?", (stamp, host_id))
    con.commit()
    alerts.sweep(con, now=NOW)  # must not raise


def test_a_naive_timestamp_is_read_as_utc(con):
    """Rows written before this module existed may have no offset. Comparing a
    naive datetime with an aware one raises, which would kill the sweep."""
    host_id = add(con, "legacy", last_report=NOW - timedelta(hours=3))
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                ((NOW - timedelta(hours=3)).replace(tzinfo=None).isoformat(), host_id))
    con.commit()
    result = alerts.sweep(con, now=NOW)
    assert result["raised"] == ["legacy"]


def test_sweep_state_survives_a_missing_row(con):
    con.execute("DELETE FROM sweep_state")
    con.commit()
    add(con, "quiet", last_report=NOW - timedelta(hours=3))
    result = alerts.sweep(con, now=NOW)
    assert result["raised"] == ["quiet"]


def test_init_is_idempotent(con):
    alerts.init(con)
    alerts.init(con)
    assert con.execute("SELECT COUNT(*) FROM sweep_state").fetchone()[0] == 1


def test_the_sweep_does_not_touch_the_reports_table(con):
    """It reads hosts and the clock. Nothing here should ever write evidence."""
    add(con, "quiet", last_report=NOW - timedelta(hours=3))
    before = con.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    alerts.sweep(con, now=NOW)
    assert con.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == before


def test_a_foreign_key_is_enforced_on_alerts(con):
    with pytest.raises(sqlite3.IntegrityError):
        alerts.raise_alert(con, 9999, alerts.KIND_SILENT, "no such host", NOW)


# ------------------------------------------------- the threshold has one owner

def test_the_dashboard_and_the_sweep_use_the_same_silence_threshold():
    """`app/alerts.py` owns the number. site/app/render_live.py carries it too,
    for the display half, and the two packages are both called `app` so neither
    can import the other. This reads the file instead.

    A dashboard saying silent while the sweep says fine is worse than either
    answer on its own, and that drift is exactly what one owner per
    fact is for.
    """
    import pathlib
    import re
    renderer = (pathlib.Path(__file__).resolve().parents[2]
                / "site" / "app" / "render_live.py")
    if not renderer.exists():
        pytest.skip("site/ is not laid out beside controlplane/ here")
    match = re.search(r"^SILENT_AFTER\s*=\s*(\d+)\s*\*\s*60", renderer.read_text(), re.M)
    assert match, "render_live.py no longer defines SILENT_AFTER in minutes"
    assert int(match.group(1)) * 60 == alerts.SILENT_AFTER_SECONDS, (
        "the dashboard and the sweep disagree about when a host is silent")


# ================================ delivery on a channel that is not email
#
# `alerts.notified_at` means a mail relay accepted the message and two screens
# say "mailed" from it in those words. Every other channel is recorded in
# `alert_deliveries`, so neither is a copy of the other.


def an_open_alert(con, name="box"):
    host_id = add(con, name)
    alert, _ = alerts.raise_alert(con, host_id, alerts.KIND_SILENT,
                                  "stopped reporting", NOW)
    return host_id, alert


def test_a_new_alert_is_pending_on_every_channel(con):
    _host_id, alert = an_open_alert(con)
    pending = alerts.pending_for_channel(con, alerts.CHANNEL_WEBHOOK)
    assert [row["id"] for row in pending] == [alert["id"]]


def test_a_destination_hears_only_what_was_raised_after_it_was_added(con):
    """Decided on 26 October 2026, after the second big test's E10a: a
    Webhook added during an open silence was sent that silence at the next
    sweep. An alert raised before a destination was added stays with the
    destinations that were there."""
    _host_id, alert = an_open_alert(con)
    after = (NOW + timedelta(minutes=1)).isoformat()
    before = (NOW - timedelta(minutes=1)).isoformat()
    assert alerts.pending_for_channel(con, alerts.CHANNEL_WEBHOOK, added_at=after) == []
    assert [row["id"] for row in alerts.pending_for_channel(
        con, alerts.CHANNEL_WEBHOOK, added_at=before)] == [alert["id"]]
    assert [row["id"] for row in alerts.pending_for_channel(
        con, alerts.CHANNEL_WEBHOOK, added_at=NOW.isoformat())] == [alert["id"]]


def test_a_delivered_alert_leaves_that_channels_queue(con):
    _host_id, alert = an_open_alert(con)
    alerts.mark_delivered(con, alert["id"], alerts.CHANNEL_WEBHOOK, NOW)
    assert alerts.pending_for_channel(con, alerts.CHANNEL_WEBHOOK) == []


def test_one_channel_succeeding_does_not_deliver_for_another(con):
    """The whole reason this table exists. A mail that was accepted beside a
    webhook that timed out has to leave the webhook retryable without sending
    the mail twice."""
    _host_id, alert = an_open_alert(con)
    alerts.mark_notified(con, alert["id"], NOW)

    # Email took it, so it is gone from the mail queue.
    assert alerts.pending_notifications(con) == []
    # The webhook did not, so it is still on its own.
    assert [r["id"] for r in alerts.pending_for_channel(
        con, alerts.CHANNEL_WEBHOOK)] == [alert["id"]]


def test_a_webhook_delivery_does_not_stamp_the_mail_column(con):
    """Reading them as one would put "mailed" on a screen about an alert no
    relay ever saw."""
    _host_id, alert = an_open_alert(con)
    alerts.mark_delivered(con, alert["id"], alerts.CHANNEL_WEBHOOK, NOW)
    row = con.execute("SELECT notified_at FROM alerts WHERE id = ?",
                      (alert["id"],)).fetchone()
    assert row["notified_at"] is None
    assert [r["id"] for r in alerts.pending_notifications(con)] == [alert["id"]]


def test_recording_the_same_delivery_twice_is_one_row(con):
    """Delivery is retried per sweep, and a retry that raced a success must
    not double-record."""
    _host_id, alert = an_open_alert(con)
    alerts.mark_delivered(con, alert["id"], alerts.CHANNEL_WEBHOOK, NOW)
    alerts.mark_delivered(con, alert["id"], alerts.CHANNEL_WEBHOOK,
                          NOW + timedelta(minutes=5))
    rows = con.execute("SELECT delivered_at FROM alert_deliveries").fetchall()
    assert len(rows) == 1
    # The first stamp stands. It is when the channel actually took it.
    assert rows[0]["delivered_at"] == NOW.isoformat()


def test_a_resolved_alert_is_not_pending_on_any_channel(con):
    host_id, alert = an_open_alert(con)
    alerts.resolve_alert(con, host_id, alerts.KIND_SILENT, NOW)
    assert alerts.pending_for_channel(con, alerts.CHANNEL_WEBHOOK) == []


def test_a_suppressed_alert_never_reaches_a_channel(con):
    """A mute suppresses rather than queues (docs/PRODUCT.md 4c), so it must
    not come back on a second channel that was added later."""
    _host_id, alert = an_open_alert(con)
    alerts.suppress_alert(con, alert["id"], NOW)
    assert alerts.pending_for_channel(con, alerts.CHANNEL_WEBHOOK) == []


def test_two_channels_are_two_independent_queues(con):
    _host_id, alert = an_open_alert(con)
    alerts.mark_delivered(con, alert["id"], "webhook", NOW)
    assert alerts.pending_for_channel(con, "webhook") == []
    assert [r["id"] for r in alerts.pending_for_channel(con, "somewhere-else")] \
        == [alert["id"]]


def test_the_queue_carries_the_host_name(con):
    """Every formatter takes a host name, so the row has to carry one or the
    caller goes back to the database per alert."""
    _host_id, alert = an_open_alert(con, name="almabox")
    row = alerts.pending_for_channel(con, alerts.CHANNEL_WEBHOOK)[0]
    assert row["host_name"] == "almabox"
