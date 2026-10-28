"""Alerting when a finding changes.

    python -m pytest tests/test_finding_alerts.py

Written before `app/finding_alerts.py` existed and run red first, the method
`docs/RECORD.md` 4.46, 4.48 and 4.51 argue for: a guard nobody has tried to
break is not evidence.

The mutations these are built to catch, in the order they matter:

  1. **Alerting on something nobody measured.** A port whose outside view is
     `not_tested` must produce no alert of any kind, whatever was declared
     about it. That is the accuracy rule (the accuracy rule) pointed at the
     alerting engine, and every test that asserts silence here asserts the
     absence of a row rather than the absence of a mail, because a recorded
     alert is a mail the next sweep sends.
  2. **Mailing on every sweep.** `docs/PRODUCT.md` 4c opens by saying a tool
     that mails you while you are still working gets filtered inside a week.
     A flapping port, a repeated state and a muted server each have a test.
  3. **Eight ports moving at once becoming eight mails.**
  4. **Reading one address family's answer as the other's**, and reading a TCP
     measurement as a UDP one. Both are `test_join.py`'s mutations and both
     reach this module through the finding it consumes.
  5. **Our own outage becoming their alert.** The debounce clock has the same
     hole the dead-man's silence clock had, and it is closed with the same
     mechanism rather than a second one.
"""

import dataclasses
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app import (alerts, alertwords, db, finding_alerts, intent, join, notify,
                 prober, store)

NOW = datetime(2026, 8, 17, 12, 0, 0, tzinfo=timezone.utc)
DEBOUNCE = timedelta(seconds=finding_alerts.DEBOUNCE_SECONDS)


# --------------------------------------------------------------- the fixtures

def socket_row(port, family="v4", protocol="tcp", process="caddy",
               bind_address="0.0.0.0", pid=7):
    return {"protocol": protocol, "family": family, "bind_address": bind_address,
            "port": port, "process_name": process, "pid": pid}


def rule(text, rendered="full", comment=""):
    return {"text": text, "rendered": rendered, "comment": comment}


def ufw_v4(rules):
    """A ufw-shaped v4 ruleset, the shape `tests/test_join.py` uses, so a
    stale rule in this suite is built the way a real one is."""
    return {"family": "ip", "name": "filter", "chains": [
        {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter",
         "policy": "drop", "rules": [rule("counter jump ufw-user-input")]},
        {"name": "ufw-user-input", "rules": [rule(text) for text in rules]},
    ]}


def document(*, hostname="one", sockets=(), tables=(),
             sockets_status="collected", nftables_status="collected",
             collected_at_unix=1_700_000_000):
    return {
        "schema_version": 1,
        "hostname": hostname,
        "collected_at_unix": collected_at_unix,
        "sockets": {"status": sockets_status, "listening": list(sockets)},
        "nftables": {"status": nftables_status, "tables": list(tables)},
    }


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    prober.init(connection)
    intent.init(connection)
    alerts.init(connection)
    finding_alerts.init(connection)
    yield connection
    connection.close()


def add_host(con, name="one"):
    host_id, _ = store.add_host(con, name)
    return host_id


def report(con, host_id, doc, received_at="2026-08-17T11:00:00+00:00"):
    store.insert_report(con, host_id, doc.get("collected_at_unix", 0),
                        doc.get("schema_version", 1), json.dumps(doc))
    con.execute("UPDATE reports SET received_at = ? WHERE host_id = ?",
                (received_at, host_id))
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                (received_at, host_id))
    con.commit()


def probe(con, host_id, results, started_at="2026-08-17T11:30:00+00:00",
          vantage="198.51.100.7"):
    """One probe run written the way `app/prober.py` writes one. Results are
    (family, port, state) triples. Each call is a newer run, which is how a
    measurement changes: `join._probe_index` reads the newest run only."""
    cur = con.execute(
        "INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
        " VALUES (?, ?, ?, ?)", (host_id, vantage, started_at, started_at))
    run_id = cur.lastrowid
    for family, port, state in results:
        con.execute(
            "INSERT INTO probe_results (run_id, target, family, port, state,"
            " reason, measured_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run_id, "203.0.113.9", family, port, state, None, started_at))
    con.commit()
    return run_id


def all_alerts(con, kind=None):
    if kind is None:
        return con.execute("SELECT * FROM alerts ORDER BY id").fetchall()
    return con.execute("SELECT * FROM alerts WHERE kind = ? ORDER BY id",
                       (kind,)).fetchall()


def changes(con):
    return con.execute("SELECT * FROM finding_changes ORDER BY id").fetchall()


def states(con):
    return con.execute("SELECT * FROM finding_states ORDER BY id").fetchall()


def mailed(con, config=None, now=NOW):
    """Every mail the delivery step would send, as (subject, body, html).

    Asked at this suite's own clock rather than the wall clock, because a
    notice is due for a day after it was raised and every change here is
    raised in August 2026."""
    out = []
    for host_name, items in finding_alerts.pending_deliveries(con, now=now):
        out.append(notify.format_finding_changes(
            host_name, [change for _, change in items]))
    return out


def a_conflict_appears(con, host_id, *, port=443, declared="open"):
    """The commonest real transition: a port declared open, measured answering,
    then measured answering nothing. `docs/PRODUCT.md` 8b calls that a
    conflict since 2026-08-16."""
    report(con, host_id, document(sockets=[socket_row(port)]))
    intent.declare(con, "one", "tcp", port, "v4", declared)
    probe(con, host_id, [("v4", port, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)
    probe(con, host_id, [("v4", port, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T12:00:00+00:00")


# ================================================== 1. never state a finding
#                                                       nobody measured

@pytest.mark.parametrize("declared", [None, "open", "closed"])
def test_a_port_with_no_probe_run_at_all_produces_nothing(con, declared):
    """The state of production on 2026-08-17: three hosts, real documents, no
    probe runs. Whatever the operator declared, there is no measurement to
    disagree with it."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443)]))
    if declared:
        intent.declare(con, "one", "tcp", 443, "v4", declared)

    result = finding_alerts.evaluate(con, now=NOW)

    assert all_alerts(con) == []
    assert states(con) == []
    assert changes(con) == []
    assert result["not_measured"] > 0


@pytest.mark.parametrize("declared", [None, "open", "closed"])
def test_a_not_tested_probe_row_produces_nothing(con, declared):
    """A row exists and says the prober could not test it. That is the absence
    of a measurement written down, not a measurement."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443)]))
    if declared:
        intent.declare(con, "one", "tcp", 443, "v4", declared)
    probe(con, host_id, [("v4", 443, prober.STATE_NOT_TESTED)])

    finding_alerts.evaluate(con, now=NOW)

    assert all_alerts(con) == []
    assert states(con) == []


def test_a_not_tested_port_stays_invisible_across_many_passes(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443)]))
    intent.declare(con, "one", "tcp", 443, "v4", "open")
    probe(con, host_id, [("v4", 443, prober.STATE_NOT_TESTED)])
    for minute in range(0, 120, 5):
        finding_alerts.evaluate(con, now=NOW + timedelta(minutes=minute))
    assert all_alerts(con) == []
    assert changes(con) == []


def test_the_v6_half_is_not_tested_and_earns_nothing(con):
    """No host on the fleet has a globally routable IPv6 address, so every v6
    answer is honestly `not tested` (docs/RECORD.md 4.53). The v4 half moving
    must not drag the v6 half along with it."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443, family="v4"),
                                           socket_row(443, family="v6",
                                                      bind_address="::")]))
    intent.declare(con, "one", "tcp", 443, "v4", "open")
    intent.declare(con, "one", "tcp", 443, "v6", "open")
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)

    families = {row["family"] for row in states(con)}
    assert families == {"v4"}


def test_a_udp_port_is_never_given_a_tcp_measurement(con):
    """`probe_results` has no protocol column and the prober is TCP connect
    only, so a UDP port has no outside view and cannot be alerted on."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(53, protocol="udp"),
                                           socket_row(53, protocol="tcp")]))
    intent.declare(con, "one", "udp", 53, "v4", "closed")
    probe(con, host_id, [("v4", 53, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)

    protocols = {row["protocol"] for row in states(con)}
    assert protocols == {"tcp"}


def test_every_alert_ever_raised_sits_beside_a_measured_outside_view(con):
    """The property, asserted over the whole set at once rather than one path
    at a time. Whatever this engine raises, the change it raised it for names
    a prober state that is one of the measured three."""
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    raised = [row for row in changes(con)
              if row["outcome"] in (finding_alerts.OUTCOME_RAISED,
                                    finding_alerts.OUTCOME_SUPPRESSED)]
    assert raised
    for row in raised:
        assert row["outside"] in prober.MEASURED_STATES


# ============================================ 2. a first pass is a baseline

def test_the_first_pass_on_a_host_records_and_raises_nothing(con):
    """The same rule the dead-man switch follows: a host it has never seen
    raises nothing, because there is no previous state for the change to be a
    change from. The cost is named rather than hidden: a port that was already
    in conflict when the prober first ran is on the screen and not in a mail."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443)]))
    intent.declare(con, "one", "tcp", 443, "v4", "closed")
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)])

    result = finding_alerts.evaluate(con, now=NOW)

    assert all_alerts(con) == []
    assert [row["state"] for row in states(con)] == [join.STATE_CONFLICT]
    assert result["baselines"] == 1


def test_a_port_that_appears_after_the_first_pass_is_a_real_change(con):
    """A new service on a host we have already measured is exactly the alert
    this product exists to send."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22), socket_row(443)]))
    probe(con, host_id, [("v4", 22, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)

    probe(con, host_id, [("v4", 22, prober.STATE_CONNECTED),
                         ("v4", 443, prober.STATE_CONNECTED)],
          started_at="2026-08-17T12:00:00+00:00")
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    open_rows = [row for row in all_alerts(con, finding_alerts.KIND_FINDING)
                 if row["resolved_at"] is None]
    assert [row["subject"] for row in open_rows] == ["tcp/443 v4"]
    assert "had no state" in open_rows[0]["detail"]


# ==================================================== 3. only real transitions

def test_a_state_that_does_not_change_raises_nothing(con):
    """Twelve sweeps an hour. The number that decides whether this feature
    survives contact with a real fleet."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443)]))
    intent.declare(con, "one", "tcp", 443, "v4", "closed")
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)])
    for minute in range(0, 24 * 60, 5):
        finding_alerts.evaluate(con, now=NOW + timedelta(minutes=minute))

    assert all_alerts(con) == []
    assert changes(con) == []


def test_a_conflict_raises_one_alert_after_the_debounce_window(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)

    held = finding_alerts.evaluate(con, now=NOW)
    assert held["raised"] == []
    assert held["holding"] == ["one tcp/443 v4"]
    assert all_alerts(con) == []

    settled = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    assert settled["raised"] == ["one tcp/443 v4"]
    rows = all_alerts(con, finding_alerts.KIND_FINDING)
    assert len(rows) == 1
    assert rows[0]["subject"] == "tcp/443 v4"
    assert "was intended, now conflict" in rows[0]["detail"]
    assert "tcp/443 on v4" in rows[0]["detail"]


def test_the_alert_is_raised_once_however_many_sweeps_follow(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    for minute in range(0, 6 * 60, 5):
        finding_alerts.evaluate(con, now=NOW + timedelta(minutes=minute))
    assert len(all_alerts(con, finding_alerts.KIND_FINDING)) == 1


def test_a_state_that_stops_asking_for_attention_resolves_the_alert(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    later = NOW + timedelta(hours=1)
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)],
          started_at="2026-08-17T13:00:00+00:00")
    finding_alerts.evaluate(con, now=later)
    result = finding_alerts.evaluate(con, now=later + DEBOUNCE)

    assert result["noted"] == ["one tcp/443 v4"]
    rows = all_alerts(con, finding_alerts.KIND_FINDING)
    assert len(rows) == 1
    assert rows[0]["resolved_at"] is not None


def test_a_move_between_two_alertable_states_resolves_and_raises_again(con):
    """The open list carries one row per port, and it says what is true now.
    Resolving before raising is what makes that possible: `raise_alert`
    returns the existing open row otherwise and the detail would still
    describe the state before last."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443)]))
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)          # baseline: unreviewed

    intent.declare(con, "one", "tcp", 443, "v4", "closed")
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)   # unreviewed to conflict

    intent.clear(con, "one", "tcp", 443, "v4")
    later = NOW + timedelta(hours=2)
    finding_alerts.evaluate(con, now=later)
    finding_alerts.evaluate(con, now=later + DEBOUNCE)  # conflict to unreviewed

    rows = all_alerts(con, finding_alerts.KIND_FINDING)
    assert len(rows) == 2
    assert rows[0]["resolved_at"] is not None
    assert rows[1]["resolved_at"] is None
    assert "was conflict, now unreviewed" in rows[1]["detail"]


def test_a_stale_rule_never_raises(con):
    """A rule permitting a port with nothing behind it is not a reachability
    change. `docs/PRODUCT.md` 4c lists the three transitions that are, and
    this is none of them."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4(["ip protocol tcp tcp dport 9000 counter accept"])]))
    probe(con, host_id, [("v4", 22, prober.STATE_CONNECTED),
                         ("v4", 9000, prober.STATE_NO_RESPONSE)])
    finding_alerts.evaluate(con, now=NOW)

    intent.declare(con, "one", "tcp", 22, "v4", "closed")
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    subjects = [row["subject"] for row in all_alerts(con, finding_alerts.KIND_FINDING)]
    assert subjects == ["tcp/22 v4"]


def test_intended_never_raises(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443)]))
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)          # baseline: unreviewed

    intent.declare(con, "one", "tcp", 443, "v4", "open")
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    assert result["raised"] == []
    assert result["noted"] == ["one tcp/443 v4"]
    assert all_alerts(con, finding_alerts.KIND_FINDING) == []


# ============================================================== 4. debounce

def test_a_change_that_reverts_inside_the_window_is_never_mailed(con):
    """`docs/PRODUCT.md` 4c: a change that reverts within 15 minutes is
    written to history and never mailed."""
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW + timedelta(minutes=5))

    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)],
          started_at="2026-08-17T12:10:00+00:00")
    result = finding_alerts.evaluate(con, now=NOW + timedelta(minutes=10))

    assert result["reverted"] == ["one tcp/443 v4"]
    assert all_alerts(con) == []
    assert mailed(con) == []


def test_a_reverted_change_is_still_written_to_history(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW + timedelta(minutes=5))
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)],
          started_at="2026-08-17T12:10:00+00:00")
    finding_alerts.evaluate(con, now=NOW + timedelta(minutes=10))

    rows = changes(con)
    assert len(rows) == 1
    assert rows[0]["outcome"] == finding_alerts.OUTCOME_REVERTED
    assert rows[0]["from_state"] == join.STATE_INTENDED
    assert rows[0]["to_state"] == join.STATE_CONFLICT
    assert rows[0]["alert_id"] is None


def test_a_port_that_flaps_for_an_hour_never_mails(con):
    """Recreating a stack does this. Twelve flaps and not one mail."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443)]))
    intent.declare(con, "one", "tcp", 443, "v4", "open")
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)

    for step in range(1, 13):
        state = (prober.STATE_NO_RESPONSE if step % 2 else prober.STATE_CONNECTED)
        probe(con, host_id, [("v4", 443, state)],
              started_at=(NOW + timedelta(minutes=5 * step)).isoformat())
        finding_alerts.evaluate(con, now=NOW + timedelta(minutes=5 * step))

    assert all_alerts(con) == []
    assert mailed(con) == []


def test_a_third_state_supersedes_the_candidate_and_restarts_the_clock(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443)]))
    intent.declare(con, "one", "tcp", 443, "v4", "open")
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)              # baseline: intended

    probe(con, host_id, [("v4", 443, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T12:01:00+00:00")
    finding_alerts.evaluate(con, now=NOW + timedelta(minutes=5))   # conflict

    # The third state. The declaration goes away and the port answers again,
    # so this is `unreviewed`. It has to be a state that can be alerted on, or
    # the two assertions at the end of this test stop distinguishing anything:
    # a third state that is merely noted produces an empty `raised` list
    # whether the clock restarted or not. Since 2026-08-28 an undeclared
    # silence is `not reachable` and is not alertable, which is exactly the
    # trap this comment exists to keep the next edit out of.
    intent.clear(con, "one", "tcp", 443, "v4")
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)],
          started_at="2026-08-17T12:11:00+00:00")
    result = finding_alerts.evaluate(con, now=NOW + timedelta(minutes=12))

    assert result["superseded"] == ["one tcp/443 v4"]
    assert all_alerts(con) == []

    # The clock restarted, so the window is measured from minute 12 and not
    # from minute 5. Fourteen minutes later is still inside it.
    result = finding_alerts.evaluate(con, now=NOW + timedelta(minutes=26))
    assert result["raised"] == []
    result = finding_alerts.evaluate(con, now=NOW + timedelta(minutes=28))
    assert result["raised"] == ["one tcp/443 v4"]


def test_the_window_is_fifteen_minutes(con):
    assert finding_alerts.DEBOUNCE_SECONDS == 15 * 60


# ============================================================= 5. coalescing

def test_eight_ports_moving_at_once_produce_one_mail(con):
    """`docs/PRODUCT.md` 4c: recreating a stack moves eight ports at once, and
    that is one mail rather than eight."""
    ports = list(range(8000, 8008))
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(port) for port in ports]))
    for port in ports:
        intent.declare(con, "one", "tcp", port, "v4", "open")
    probe(con, host_id, [("v4", port, prober.STATE_CONNECTED) for port in ports])
    finding_alerts.evaluate(con, now=NOW)

    probe(con, host_id, [("v4", port, prober.STATE_NO_RESPONSE) for port in ports],
          started_at="2026-08-17T12:00:00+00:00")
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    assert len(result["raised"]) == 8
    assert len(all_alerts(con, finding_alerts.KIND_FINDING)) == 8

    letters = mailed(con)
    assert len(letters) == 1
    subject, body, _html = letters[0]
    # One mail, and it counts ports. It names five and says how many more.
    assert subject == "[whichports] 8 ports changed on one"
    assert "  stopped answering: 8000, 8001, 8002, 8003, 8004 and 3 more\n" in body


def test_two_hosts_moving_at_once_produce_one_mail_each(con):
    """Coalescing is per server. One mail about two machines would put the
    reader's own hostname somewhere in the middle of a list."""
    for name in ("one", "two"):
        host_id = add_host(con, name)
        report(con, host_id, document(hostname=name, sockets=[socket_row(443)]))
        intent.declare(con, name, "tcp", 443, "v4", "open")
        probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)

    for host in con.execute("SELECT id FROM hosts").fetchall():
        probe(con, host["id"], [("v4", 443, prober.STATE_NO_RESPONSE)],
              started_at="2026-08-17T12:00:00+00:00")
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    letters = mailed(con)
    assert len(letters) == 2
    assert [subject for subject, _, _h in letters] == [
        "[whichports] Port 443 on one does not answer from the internet",
        "[whichports] Port 443 on two does not answer from the internet"]


def test_ports_that_move_on_different_sweeps_are_two_mails(con):
    """Coalescing is not batching. Two ports that genuinely moved at
    different times are two pieces of news."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(80), socket_row(443)]))
    for port in (80, 443):
        intent.declare(con, "one", "tcp", port, "v4", "open")
    probe(con, host_id, [("v4", 80, prober.STATE_CONNECTED),
                         ("v4", 443, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)

    probe(con, host_id, [("v4", 80, prober.STATE_NO_RESPONSE),
                         ("v4", 443, prober.STATE_CONNECTED)],
          started_at="2026-08-17T12:00:00+00:00")
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    first = mailed(con)
    assert len(first) == 1
    for alert_id, _ in finding_alerts.pending_deliveries(con)[0][1]:
        alerts.mark_notified(con, alert_id, NOW + DEBOUNCE)

    later = NOW + timedelta(hours=3)
    probe(con, host_id, [("v4", 80, prober.STATE_NO_RESPONSE),
                         ("v4", 443, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T15:00:00+00:00")
    finding_alerts.evaluate(con, now=later)
    finding_alerts.evaluate(con, now=later + DEBOUNCE)
    second = mailed(con)
    assert len(second) == 1
    assert second[0][0] == "[whichports] Port 443 on one does not answer from the internet"
    assert "  port: 443\n" in second[0][1]
    assert "port: 80" not in second[0][1]


# ================================================ 6. mute and per-port silence

def test_a_muted_server_records_the_change_and_mails_nothing(con):
    """`docs/PRODUCT.md` 4c: changes are still recorded, they just do not
    mail. So the alert is on the screen and no letter leaves the box."""
    host_id = add_host(con)
    finding_alerts.mute_host(con, "one", now=NOW)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    assert result["raised"] == []
    assert result["suppressed"] == ["one tcp/443 v4"]
    rows = all_alerts(con, finding_alerts.KIND_FINDING)
    assert len(rows) == 1
    assert rows[0]["resolved_at"] is None
    assert rows[0]["suppressed_at"] is not None
    assert rows[0]["notified_at"] is None
    assert mailed(con) == []


def test_a_suppressed_alert_is_never_mailed_late(con):
    """Mute suppresses, it does not queue. A letter about work that finished
    two hours ago is the thing 4c is trying to prevent."""
    host_id = add_host(con)
    finding_alerts.mute_host(con, "one", now=NOW)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    after = NOW + timedelta(hours=4)
    finding_alerts.evaluate(con, now=after)
    assert mailed(con) == []
    assert alerts.pending_notifications(con) == []


def test_the_default_mute_is_two_hours(con):
    assert finding_alerts.DEFAULT_MUTE_SECONDS == 2 * 60 * 60
    host_id = add_host(con)
    finding_alerts.mute_host(con, "one", now=NOW)
    assert finding_alerts.silenced(con, host_id, "tcp", 443, "v4",
                                  now=NOW + timedelta(hours=1)) == \
        finding_alerts.SILENCE_MUTE
    assert finding_alerts.silenced(con, host_id, "tcp", 443, "v4",
                                  now=NOW + timedelta(hours=3)) is None


def test_a_change_after_the_mute_expires_mails(con):
    host_id = add_host(con)
    finding_alerts.mute_host(con, "one", now=NOW - timedelta(hours=3))
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    assert result["raised"] == ["one tcp/443 v4"]
    assert len(mailed(con)) == 1


def test_unmuting_a_server_takes_effect_immediately(con):
    host_id = add_host(con)
    finding_alerts.mute_host(con, "one", now=NOW)
    assert finding_alerts.unmute_host(con, "one", now=NOW) is True
    assert finding_alerts.silenced(con, host_id, "tcp", 443, "v4", now=NOW) is None


def test_an_indefinite_mute_stores_no_expiry_and_never_lapses(con):
    """`seconds=None` is "until I turn it back on": a row with no `until` at
    all, the same convention a permanent per-port silence has always used, so
    the one reader keeps one rule for what an absent expiry means."""
    host_id = add_host(con)
    finding_alerts.mute_host(con, "one", seconds=None, now=NOW)
    row = con.execute("SELECT * FROM alert_silences WHERE cleared_at IS NULL"
                      ).fetchone()
    assert row["until"] is None
    far = NOW + timedelta(days=4000)
    assert finding_alerts.silenced(con, host_id, "tcp", 443, "v4", now=far) == \
        finding_alerts.SILENCE_MUTE


def test_an_indefinite_mute_ends_only_by_unmuting(con):
    host_id = add_host(con)
    finding_alerts.mute_host(con, "one", seconds=None, now=NOW)
    assert finding_alerts.unmute_host(con, "one", now=NOW) is True
    assert finding_alerts.silenced(con, host_id, "tcp", 443, "v4", now=NOW) is None


def test_a_change_under_an_indefinite_mute_is_recorded_and_never_mails(con):
    """The same treatment a timed mute gives a change, held long past any
    length a timed mute could have had."""
    host_id = add_host(con)
    finding_alerts.mute_host(con, "one", seconds=None,
                             now=NOW - timedelta(days=365))
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    assert result["raised"] == []
    assert result["suppressed"] == ["one tcp/443 v4"]
    assert mailed(con) == []


@pytest.mark.parametrize("seconds", [0, -1, -3600])
def test_a_mute_for_no_time_at_all_is_refused_by_the_store(con, seconds):
    """The refusal lives in the store rather than only in its callers, so a
    new caller cannot write a mute that was over before it began."""
    add_host(con)
    with pytest.raises(ValueError):
        finding_alerts.mute_host(con, "one", seconds=seconds, now=NOW)
    assert con.execute("SELECT COUNT(*) FROM alert_silences").fetchone()[0] == 0


def test_a_silenced_port_never_mails_and_its_neighbour_still_does(con):
    """`docs/PRODUCT.md` 4c: permanent per-port silence. One port going quiet
    for ever must not take the port next to it with it."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(80), socket_row(443)]))
    for port in (80, 443):
        intent.declare(con, "one", "tcp", port, "v4", "open")
    probe(con, host_id, [("v4", 80, prober.STATE_CONNECTED),
                         ("v4", 443, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.silence_port(con, "one", "tcp", 80, "v4", now=NOW)

    probe(con, host_id, [("v4", 80, prober.STATE_NO_RESPONSE),
                         ("v4", 443, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T12:00:00+00:00")
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    assert result["suppressed"] == ["one tcp/80 v4"]
    assert result["raised"] == ["one tcp/443 v4"]
    letters = mailed(con)
    assert len(letters) == 1
    assert letters[0][0] == "[whichports] Port 443 on one does not answer from the internet"
    assert "  port: 443\n" in letters[0][1]
    assert "port: 80" not in letters[0][1]


def test_a_port_silence_never_expires(con):
    host_id = add_host(con)
    finding_alerts.silence_port(con, "one", "tcp", 80, "v4", now=NOW)
    far = NOW + timedelta(days=4000)
    assert finding_alerts.silenced(con, host_id, "tcp", 80, "v4", now=far) == \
        finding_alerts.SILENCE_PORT


def test_a_port_silence_covers_one_family_only(con):
    host_id = add_host(con)
    finding_alerts.silence_port(con, "one", "tcp", 80, "v4", now=NOW)
    assert finding_alerts.silenced(con, host_id, "tcp", 80, "v6", now=NOW) is None
    assert finding_alerts.silenced(con, host_id, "tcp", 80, "v4", now=NOW) is not None


def test_a_port_silence_covers_one_protocol_only(con):
    host_id = add_host(con)
    finding_alerts.silence_port(con, "one", "tcp", 53, "v4", now=NOW)
    assert finding_alerts.silenced(con, host_id, "udp", 53, "v4", now=NOW) is None


def test_muting_an_unknown_host_is_refused(con):
    with pytest.raises(intent.IntentError):
        finding_alerts.mute_host(con, "nosuchhost", now=NOW)


def test_listing_silences_reports_what_is_live(con):
    add_host(con)
    finding_alerts.mute_host(con, "one", now=NOW)
    finding_alerts.silence_port(con, "one", "tcp", 80, "v4", now=NOW)
    live = finding_alerts.list_silences(con, now=NOW)
    assert [row["kind"] for row in live] == [finding_alerts.SILENCE_PORT,
                                            finding_alerts.SILENCE_MUTE]
    assert finding_alerts.list_silences(con, now=NOW + timedelta(hours=3)) == \
        [row for row in live if row["kind"] == finding_alerts.SILENCE_PORT]


# =============================================== 7. our own outage, and pause

def test_our_own_outage_holds_a_candidate_for_one_window_after_recovery(con):
    """The dead-man's guard, pointed at the debounce clock. While the control
    plane was down it could not have seen a revert, so a candidate first seen
    before the outage is held for one window measured from the recovery
    rather than confirmed the moment we come back.

    Solved with the mechanism `app/alerts.py` already chose rather than a
    second one: a recovery point, no deadline to re-arm."""
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    assert all_alerts(con) == []

    # The sweeper stops. alerts.sweep detects the gap on its first run back
    # and stamps the recovery point, which is the only thing that moves it.
    recovery = NOW + timedelta(hours=5)
    con.execute("UPDATE sweep_state SET last_sweep_at = ? WHERE id = 1",
                (NOW.isoformat(),))
    con.commit()
    outage = alerts.sweep(con, now=recovery)
    assert outage["self_outage"] is True

    result = finding_alerts.evaluate(con, now=recovery)
    assert result["raised"] == []
    assert result["holding"] == ["one tcp/443 v4"]


def test_the_recovery_point_delays_a_real_change_and_does_not_cancel_it(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)

    recovery = NOW + timedelta(hours=5)
    con.execute("UPDATE sweep_state SET last_sweep_at = ? WHERE id = 1",
                (NOW.isoformat(),))
    con.commit()
    alerts.sweep(con, now=recovery)
    finding_alerts.evaluate(con, now=recovery)

    result = finding_alerts.evaluate(con, now=recovery + DEBOUNCE)
    assert result["raised"] == ["one tcp/443 v4"]


def test_a_normal_gap_between_sweeps_delays_nothing(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    con.execute("UPDATE sweep_state SET last_sweep_at = ? WHERE id = 1",
                (NOW.isoformat(),))
    con.commit()
    alerts.sweep(con, now=NOW + timedelta(minutes=5))
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    assert result["raised"] == ["one tcp/443 v4"]


def test_a_paused_host_still_gets_a_finding_alert(con):
    """`docs/PRODUCT.md` 4c guard 1: a per-server monitoring pause suppresses
    only the silence alert, never a real finding. Mute is the other control
    and it is a different row."""
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    store.pause_host(con, "one", True)
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    assert result["raised"] == ["one tcp/443 v4"]


def test_a_revoked_host_is_not_evaluated_and_its_alerts_close(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    assert len(all_alerts(con, finding_alerts.KIND_FINDING)) == 1

    store.revoke_host(con, "one")
    later = NOW + timedelta(hours=1)
    result = finding_alerts.evaluate(con, now=later)
    assert result["closed"] == ["one"]
    rows = all_alerts(con, finding_alerts.KIND_FINDING)
    assert rows[0]["resolved_at"] is not None
    assert mailed(con) == []


# =========================================================== 8. the delivery

def test_a_suppressed_alert_is_not_pending_and_the_silence_alert_still_is(con):
    """`pending_notifications` is what the sweep delivers from, and a
    suppressed row must leave it without ever claiming it was mailed."""
    host_id = add_host(con)
    finding_alerts.mute_host(con, "one", now=NOW)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    alerts.raise_alert(con, host_id, alerts.KIND_SILENT, "no report", NOW)
    con.commit()
    pending = alerts.pending_notifications(con)
    assert [row["kind"] for row in pending] == [alerts.KIND_SILENT]


def test_a_failed_delivery_is_retried_and_never_raised_twice(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    assert len(mailed(con)) == 1
    assert len(mailed(con)) == 1        # nothing stamped it, so it is still due
    assert len(all_alerts(con, finding_alerts.KIND_FINDING)) == 1


def test_a_delivered_alert_stops_being_due(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    for alert_id, _ in finding_alerts.pending_deliveries(con)[0][1]:
        alerts.mark_notified(con, alert_id, NOW)
    assert mailed(con) == []


# ============================================================= 9. the letter

BANNED = ("secure", "protected", "safe", "compliant", "guaranteed", "certified",
          "vulnerable", "risk", "score", "grade")

# Explaining the restraint is its own failure. The writing rules: the
# absence is the statement, and a sentence saying so reads as covering
# ourselves. `app/notify.format_silence` had exactly this in its first draft.
POSTURE = ("we report", "you draw", "not a conclusion", "not a verdict",
           "draw the conclusion", "this does not mean", "we do not claim")


def every_letter(con):
    """Every piece of prose a reader sees, both halves of the mail.

    The designed half is reduced to its visible text first. The writing rules
    in the writing rules are about prose, and a stylesheet is full of
    hyphens and semicolons that are not prose, so asserting them against raw
    markup would fail on `letter-spacing` and prove nothing about what anybody
    reads.
    """
    return [text
            for subject, body, html in mailed(con)
            for text in (subject, body, visible_text(html))]


def visible_text(html):
    """What a reader sees: no head, no tags, entities resolved."""
    import html as html_module
    import re
    without_head = re.sub(r"<head\b.*?</head>", " ", html, flags=re.S | re.I)
    without_tags = re.sub(r"<[^>]+>", " ", without_head)
    return html_module.unescape(re.sub(r"\s+", " ", without_tags))


def sample_letters(con):
    """Enough shapes of the letter that the language tests see all of it: one
    change, eight changes, a port with no previous state, and a change whose
    cause quotes a rule."""
    host_id = add_host(con)
    ports = [80, 443, 2019]
    report(con, host_id, document(
        sockets=[socket_row(port) for port in ports],
        tables=[ufw_v4([f"ip protocol tcp tcp dport {port} counter accept"
                        for port in ports])]))
    for port in ports:
        intent.declare(con, "one", "tcp", port, "v4", "open")
    probe(con, host_id, [("v4", port, prober.STATE_CONNECTED) for port in ports])
    finding_alerts.evaluate(con, now=NOW)
    probe(con, host_id, [("v4", port, prober.STATE_NO_RESPONSE) for port in ports],
          started_at="2026-08-17T12:00:00+00:00")
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    return every_letter(con)


def test_the_letter_uses_no_word_we_are_not_allowed_to_use(con):
    """The writing rules, held the way `tests/test_join.py` holds
    `join.describe`."""
    texts = sample_letters(con)
    assert texts
    for text in texts:
        lowered = text.lower()
        for word in BANNED:
            assert word not in lowered, f"{word!r} in {text!r}"


def test_the_letter_never_explains_our_own_posture(con):
    for text in sample_letters(con):
        lowered = text.lower()
        for phrase in POSTURE:
            assert phrase not in lowered, f"{phrase!r} in {text!r}"


def test_the_letter_has_no_dash_and_no_semicolon(con):
    for text in sample_letters(con):
        assert "—" not in text and "–" not in text
        assert ";" not in text


def test_the_letter_names_the_server_the_port_and_what_you_said(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    subject, body, _html = mailed(con)[0]

    assert subject == "[whichports] Port 443 on one does not answer from the internet"
    assert ("  server: one\n  port: 443\n  you said: reachable\n"
            "  program: caddy\n") in body
    assert "Nothing else will be sent about this port until it changes again." in body
    # Its one link is the server's own page.
    assert "  https://app.whichports.com/host/one\n" in body
    # No state word, and the vantage's address stays on the server's page.
    assert "intended" not in body and "conflict" not in body
    assert "198.51.100.7" not in body


def test_the_letter_states_no_reachability_the_prober_did_not_measure(con):
    """What the letter says of reachability is the outside answer frozen
    with the change, and nothing on top of it."""
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    subject, body, _html = mailed(con)[0]
    row = [r for r in changes(con) if r["outcome"] == finding_alerts.OUTCOME_RAISED][-1]
    assert row["outside"] == prober.STATE_NO_RESPONSE
    assert "does not answer from the internet" in subject
    assert "is reachable" not in subject + body
    assert "not tested" not in body
    # What stopped the packet is not said, by any name.
    assert "firewall" not in body and "allowed by" not in body


def test_the_letter_counts_ports_and_not_findings(con):
    """Three ports, each changed in both address families: six findings,
    three ports, and each port named once."""
    ports = [8000, 8001, 8002]
    host_id = add_host(con)
    report(con, host_id, document(sockets=(
        [socket_row(port) for port in ports]
        + [socket_row(port, family="v6", bind_address="::") for port in ports])))
    for port in ports:
        for family in ("v4", "v6"):
            intent.declare(con, "one", "tcp", port, family, "open")
    both = [(family, port) for port in ports for family in ("v4", "v6")]
    probe(con, host_id, [(f, port, prober.STATE_CONNECTED) for f, port in both])
    finding_alerts.evaluate(con, now=NOW)
    probe(con, host_id, [(f, port, prober.STATE_NO_RESPONSE) for f, port in both],
          started_at="2026-08-17T12:00:00+00:00")
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    assert len(result["raised"]) == 6

    subject, body, _html = mailed(con)[0]
    assert subject == "[whichports] 3 ports changed on one"
    assert "  stopped answering: 8000, 8001, 8002\n" in body


def test_a_letter_for_a_port_with_no_previous_state_reads_correctly(con):
    change = notify.Change(where="tcp/443 on v4", was="", now="conflict",
                           description="tcp/443 on v4: conflict.",
                           vantage="198.51.100.7",
                           measured_at="2026-08-17T12:00:00+00:00",
                           port=443, family="v4", answers=True)
    _, body, _html = notify.format_finding_changes("one", [change])
    # A port seen for the first time reads as any other. The letter says
    # nothing of a state, so it has nothing to say about there being none.
    assert "state" not in body and "conflict" not in body
    assert "  port: 443\n  you said: closed\n" in body


def test_a_letter_with_no_vantage_says_nothing_about_where_it_came_from(con):
    """A reachability finding without a vantage point is not a finding
    (docs/RECORD.md 4.54). A run stored before that rule has none, and the
    letter leaves the line out rather than inventing one."""
    change = notify.Change(where="tcp/443 on v4", was="intended", now="conflict",
                           description="tcp/443 on v4: conflict.",
                           vantage="", measured_at="")
    _, body, _html = notify.format_finding_changes("one", [change])
    assert "measured from" not in body


# =========================================================== 10. the plumbing

def test_init_is_idempotent(con):
    finding_alerts.init(con)
    finding_alerts.init(con)


def test_an_unreadable_document_produces_nothing(con):
    host_id = add_host(con)
    store.insert_report(con, host_id, 0, 1, "not json at all")
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)
    assert states(con) == []
    assert all_alerts(con) == []


def test_a_host_that_never_reported_produces_nothing(con):
    add_host(con)
    finding_alerts.evaluate(con, now=NOW)
    assert states(con) == []
    assert all_alerts(con) == []


def test_the_engine_writes_nothing_to_the_measurement_tables(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    before = [con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
              for table in ("reports", "probe_runs", "probe_results",
                            "port_intents")]
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    after = [con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
             for table in ("reports", "probe_runs", "probe_results",
                           "port_intents")]
    assert before == after


def test_a_foreign_key_is_enforced_on_a_silence(con):
    with pytest.raises(Exception):
        con.execute("INSERT INTO alert_silences (host_id, kind, created_at)"
                    " VALUES (999, 'mute', '2026-08-17T12:00:00+00:00')")
        con.commit()


def test_an_unparseable_stamp_does_not_take_the_pass_down(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    con.execute("UPDATE finding_changes SET seen_at = 'not a timestamp'")
    con.commit()
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    assert result["unreadable"] == ["one tcp/443 v4"]
    assert all_alerts(con) == []


# ========================================== nothing was watching the prober
#
# If probing stops, the last results stay in the database, the join keeps
# reporting them, and the screen keeps saying what was true yesterday.
# `docs/PRODUCT.md` 4c: the quiet reads as healthy.

STALE = timedelta(seconds=finding_alerts.OUTSIDE_STALE_AFTER_SECONDS)


def a_probed_host(con, name="one", started_at=None):
    """A host with one finished pass, stamped at NOW by default so the age
    arithmetic below is measured from a known instant rather than from the
    module's default probe time, which is already half an hour old."""
    started_at = started_at or NOW.isoformat()
    host_id = add_host(con, name)
    report(con, host_id, document(sockets=[socket_row(443)]))
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)],
          started_at=started_at)
    return host_id


def test_a_fresh_outside_view_raises_nothing(con):
    a_probed_host(con)
    result = finding_alerts.sweep_outside_views(con, now=NOW)
    assert result["stale"] == []
    assert all_alerts(con, finding_alerts.KIND_OUTSIDE_STALE) == []


def test_an_outside_view_that_stopped_being_refreshed_raises(con):
    a_probed_host(con)
    result = finding_alerts.sweep_outside_views(con, now=NOW + STALE)
    assert result["stale"] == ["one"]
    alerts_raised = all_alerts(con, finding_alerts.KIND_OUTSIDE_STALE)
    assert len(alerts_raised) == 1
    assert "in 3 hours" in alerts_raised[0]["detail"]


def test_the_threshold_boundary_is_closed(con):
    """One second inside is fresh and the threshold itself is not."""
    a_probed_host(con)
    assert finding_alerts.sweep_outside_views(
        con, now=NOW + STALE - timedelta(seconds=1))["stale"] == []
    assert finding_alerts.sweep_outside_views(
        con, now=NOW + STALE)["stale"] == ["one"]


def test_one_stale_view_is_one_alert_however_long_it_lasts(con):
    a_probed_host(con)
    finding_alerts.sweep_outside_views(con, now=NOW + STALE)
    finding_alerts.sweep_outside_views(con, now=NOW + STALE + timedelta(days=2))
    assert len(all_alerts(con, finding_alerts.KIND_OUTSIDE_STALE)) == 1


def test_probing_resuming_resolves_the_alert(con):
    host_id = a_probed_host(con)
    finding_alerts.sweep_outside_views(con, now=NOW + STALE)
    later = NOW + STALE + timedelta(minutes=5)
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)],
          started_at=later.isoformat())
    result = finding_alerts.sweep_outside_views(
        con, now=later + timedelta(minutes=1))
    assert result["resolved"] == ["one"]
    assert all(a["resolved_at"] for a in
               all_alerts(con, finding_alerts.KIND_OUTSIDE_STALE))


def test_a_host_never_probed_never_raises(con):
    """The same rule as a host that never reported (`docs/RECORD.md` 4.51).
    The alert says refreshing stopped, and a view that never started has not
    stopped. The cost is stated rather than hidden: such a host is invisible
    here and belongs on a screen."""
    host_id = add_host(con, "never")
    report(con, host_id, document(sockets=[socket_row(443)]))
    result = finding_alerts.sweep_outside_views(con, now=NOW + STALE * 10)
    assert result["never_probed"] == ["never"]
    assert all_alerts(con, finding_alerts.KIND_OUTSIDE_STALE) == []


def test_a_run_that_never_finished_is_not_a_measurement(con):
    """A row with a start and no finish is a pass that died. It must not count
    as a refresh, and it must not raise on its own either."""
    host_id = add_host(con, "one")
    report(con, host_id, document(sockets=[socket_row(443)]))
    con.execute("INSERT INTO probe_runs (host_id, vantage, started_at)"
                " VALUES (?, ?, ?)", (host_id, "v", NOW.isoformat()))
    con.commit()
    result = finding_alerts.sweep_outside_views(con, now=NOW + STALE)
    assert result["never_probed"] == ["one"]
    assert all_alerts(con, finding_alerts.KIND_OUTSIDE_STALE) == []


def test_a_revoked_host_closes_its_stale_alert(con):
    host_id = a_probed_host(con)
    finding_alerts.sweep_outside_views(con, now=NOW + STALE)
    store.revoke_host(con, "one")
    result = finding_alerts.sweep_outside_views(
        con, now=NOW + STALE + timedelta(minutes=1))
    assert result["resolved"] == ["one"]


def test_our_own_outage_holds_the_alert_rather_than_raising_it(con):
    """The same guard the silence clock uses. While this control plane was
    down no pass could have been recorded, so the gap is ours."""
    a_probed_host(con)
    # alerts.sweep detects the gap on its first run back and stamps the
    # recovery point, which is the only thing that moves it.
    recovery = NOW + STALE * 2
    con.execute("UPDATE sweep_state SET last_sweep_at = ? WHERE id = 1",
                (NOW.isoformat(),))
    con.commit()
    assert alerts.sweep(con, now=recovery)["self_outage"] is True
    result = finding_alerts.sweep_outside_views(con, now=recovery)
    assert result["stale"] == []
    assert result["held"] == ["one"]


def test_a_muted_server_still_raises_and_shows_but_does_not_mail(con):
    """`docs/PRODUCT.md` 4c's own wording, and the same treatment a finding
    change gets."""
    a_probed_host(con)
    # Longer than the staleness threshold on purpose. The default mute is two
    # hours and would have expired before the view went stale, which would
    # test nothing.
    finding_alerts.mute_host(con, "one", seconds=int(STALE.total_seconds()) * 2,
                             now=NOW)
    result = finding_alerts.sweep_outside_views(con, now=NOW + STALE)
    assert result["suppressed"] == ["one"]
    assert result["stale"] == []
    raised = all_alerts(con, finding_alerts.KIND_OUTSIDE_STALE)
    assert len(raised) == 1, "it still raises and still shows"
    assert raised[0]["suppressed_at"], "and it does not mail"


def test_the_sweep_respects_an_indefinite_mute(con):
    """A mute with no expiry covers the sweep at any distance. The timed test
    above had to be given a length longer than the staleness threshold, and
    this one has no length to outlive."""
    a_probed_host(con)
    finding_alerts.mute_host(con, "one", seconds=None, now=NOW)
    result = finding_alerts.sweep_outside_views(con, now=NOW + STALE * 100)
    assert result["suppressed"] == ["one"]
    assert result["stale"] == []
    raised = all_alerts(con, finding_alerts.KIND_OUTSIDE_STALE)
    assert len(raised) == 1, "it still raises and still shows"
    assert raised[0]["suppressed_at"], "and it does not mail"


def test_an_unreadable_finish_stamp_raises_nothing_and_says_so(con):
    """Not evidence of freshness and not evidence of staleness either."""
    host_id = a_probed_host(con)
    con.execute("UPDATE probe_runs SET finished_at = 'not a time'"
                " WHERE host_id = ?", (host_id,))
    con.commit()
    result = finding_alerts.sweep_outside_views(con, now=NOW + STALE)
    assert result["held"] == ["one"]
    assert all_alerts(con, finding_alerts.KIND_OUTSIDE_STALE) == []


# =========================== 9. a rate-limited port does not mail its own flap
#
# The owner's decision, 2026-08-21, `docs/RECORD.md` 4.81. A rate limit makes the
# same port reachable and unreachable at the same moment depending on who is
# asking and how recently, so two probes minutes apart can legitimately
# disagree about it. The flag says the disagreement is expected there.


UFW_LIMIT = ("ip protocol tcp tcp dport 443 [xt match conntrack]"
             " [xt match recent] counter jump ufw-user-limit-accept")


def limited_table(port=443):
    """A ufw-shaped v4 ruleset whose only rule is a limit on this port.

    Not `ufw_v4` above, because a limit rule jumps into a chain that has to
    exist for the walk to reach its accept, and a rule carrying a bracketed
    fallback is `partial` rather than `full`.
    """
    text = UFW_LIMIT.replace("dport 443", f"dport {port}")
    return {"family": "ip", "name": "filter", "chains": [
        {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter",
         "policy": "drop", "rules": [rule("counter jump ufw-user-input")]},
        {"name": "ufw-user-input", "rules": [rule(text, rendered="partial")]},
        {"name": "ufw-user-limit-accept", "rules": [rule("counter accept")]},
    ]}


def a_limited_conflict_appears(con, host_id, *, port=443, declared="open"):
    """`a_conflict_appears`, with a rate limit rule on the same port."""
    report(con, host_id, document(sockets=[socket_row(port)],
                                  tables=[limited_table(port)]))
    intent.declare(con, "one", "tcp", port, "v4", declared)
    probe(con, host_id, [("v4", port, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)
    probe(con, host_id, [("v4", port, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T12:00:00+00:00")


def test_the_flag_is_set_from_the_rule_and_only_then(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443), socket_row(80)],
                                  tables=[limited_table(443)]))
    result = join.host_findings(con, host_id)
    by_port = {(f.port, f.family): f for f in result.findings}
    assert by_port[(443, "v4")].rate_limited is True
    assert by_port[(80, "v4")].rate_limited is False


def test_the_flag_never_moves_a_state(con):
    """docs/PRODUCT.md 8c. `_decide` does not see it and no word changes."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443)]))
    intent.declare(con, "one", "tcp", 443, "v4", "open")
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)])
    plain = join.host_findings(con, host_id).findings[0]

    other = add_host(con, name="two")
    report(con, other, document(sockets=[socket_row(443)],
                                tables=[limited_table(443)]))
    intent.declare(con, "two", "tcp", 443, "v4", "open")
    probe(con, other, [("v4", 443, prober.STATE_CONNECTED)])
    limited = join.host_findings(con, other).findings[0]

    assert plain.state == limited.state
    assert limited.rate_limited is True and plain.rate_limited is False


def test_a_flap_on_a_rate_limited_port_is_recorded_and_not_mailed(con):
    """The thing the owner's decision buys, end to end."""
    host_id = add_host(con)
    a_limited_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(
        con, now=NOW + timedelta(seconds=finding_alerts.DEBOUNCE_SECONDS + 60))

    assert result["rate_limited"], "the flap was not recognised"
    assert result["raised"] == []
    # Recorded and on the screen, exactly like a mute. Not swallowed.
    assert changes(con)[-1]["outcome"] == finding_alerts.OUTCOME_RATE_LIMITED
    assert all_alerts(con, finding_alerts.KIND_FINDING)
    assert mailed(con) == []


def test_the_same_flap_without_the_rule_still_mails(con):
    """The control. Without the rule this is the commonest real transition
    there is and it has to keep reaching somebody."""
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(
        con, now=NOW + timedelta(seconds=finding_alerts.DEBOUNCE_SECONDS + 60))

    assert result["raised"], "a real conflict stopped being mailed"
    assert result["rate_limited"] == []
    assert mailed(con) != []


def test_a_port_going_stale_behind_a_rate_limit_still_mails(con):
    """The narrowness is the design. A rate limit changes whether a connection
    got through and nothing else, so it cannot make a listener go away.
    Suppressing every change on a rate-limited port would silence tcp/22 on
    every ufw host there is."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443)],
                                  tables=[limited_table(443)]))
    intent.declare(con, "one", "tcp", 443, "v4", "open")
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)

    # The listener goes away and the permit stays. That is `stale rule`, and a
    # rate limit cannot cause it.
    report(con, host_id, document(
        sockets=[],
        tables=[ufw_v4(["ip protocol tcp tcp dport 443 counter accept"])]))
    probe(con, host_id, [("v4", 443, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T12:00:00+00:00")
    finding_alerts.evaluate(con, now=NOW + timedelta(minutes=1))
    result = finding_alerts.evaluate(
        con, now=NOW + timedelta(seconds=finding_alerts.DEBOUNCE_SECONDS + 120))

    assert result["rate_limited"] == []


def test_a_mute_wins_over_the_flag(con):
    """Two different facts, and the operator's own decision is the one to
    record. Reading it the other way round would lose that a person asked."""
    host_id = add_host(con)
    a_limited_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.mute_host(con, "one", seconds=4 * 3600, now=NOW)
    result = finding_alerts.evaluate(
        con, now=NOW + timedelta(seconds=finding_alerts.DEBOUNCE_SECONDS + 60))

    assert result["suppressed"], "the mute stopped being recorded as a mute"
    assert result["rate_limited"] == []


def test_the_flap_word_is_not_the_mute_word(con):
    """A screen reading them as one would say somebody muted a port nobody
    touched."""
    assert (finding_alerts.OUTCOME_RATE_LIMITED
            != finding_alerts.OUTCOME_SUPPRESSED)


def test_the_flap_set_is_only_the_transitions_a_rate_limit_explains(con):
    """Six. The two declared ones, the two undeclared ones, and since
    2026-09-27 the two a rule answers, because `not reachable` to `intended`
    mails now that a port which became reachable is told once.

    What stays out is every transition that asserts something a rate limit
    cannot cause. `stale rule` means the listener went away and `unexplained`
    means nothing on the host owns the port, and no window on a rule does
    either of those.
    """
    assert finding_alerts.RATE_LIMIT_FLAP == frozenset({
        (join.STATE_INTENDED, join.STATE_CONFLICT),
        (join.STATE_CONFLICT, join.STATE_INTENDED),
        (join.STATE_UNREVIEWED, join.STATE_NOT_REACHABLE),
        (join.STATE_NOT_REACHABLE, join.STATE_UNREVIEWED),
        (join.STATE_INTENDED, join.STATE_NOT_REACHABLE),
        (join.STATE_NOT_REACHABLE, join.STATE_INTENDED)})


def test_a_port_with_no_declaration_flaps_the_same_way_a_declared_one_does(con):
    """**This test used to assert the opposite, and the thing it asserted was
    the defect.** It said an undeclared port "never flaps in the first place",
    because `_decide` answered `unreviewed` whether the port answered or not.

    That is one word for two opposite facts, and `app/finding_alerts.py` finds
    a transition by comparing state words, so a port that went from shut to
    answering the internet was not a change and mailed nothing. The one alert
    this product exists to send could not be sent for any port nobody had
    declared, which is every port on a fresh install.

    With `not reachable` (2026-08-28, RECORD 4.112) the state moves, so the
    pair has to be in the flap set above for the same reason the declared pair
    is.
    """
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443)],
                                  tables=[limited_table(443)]))
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)])
    first = join.host_findings(con, host_id).findings[0].state
    probe(con, host_id, [("v4", 443, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T12:00:00+00:00")
    second = join.host_findings(con, host_id).findings[0].state
    assert first == join.STATE_UNREVIEWED
    assert second == join.STATE_NOT_REACHABLE
    assert (first, second) in finding_alerts.RATE_LIMIT_FLAP


def test_an_undeclared_port_becoming_reachable_is_a_change_that_mails(con):
    """The alert the state split exists to make possible, end to end and with
    no rate limit anywhere near it.

    A port that is shut and undeclared is `not reachable`. Somebody opens the
    firewall. It becomes `unreviewed`, which is in `ALERTABLE_STATES`, so
    after the debounce it raises. Before 2026-08-28 both readings were
    `unreviewed`, `observed == row["state"]` was true, and this pass returned
    with nothing raised.
    """
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(9100)]))
    probe(con, host_id, [("v4", 9100, prober.STATE_NO_RESPONSE)])
    finding_alerts.evaluate(con, now=NOW)                      # baseline

    probe(con, host_id, [("v4", 9100, prober.STATE_CONNECTED)],
          started_at="2026-08-17T12:00:00+00:00")
    seen = finding_alerts.evaluate(con, now=NOW + timedelta(minutes=1))
    assert seen["holding"] == ["one tcp/9100 v4"]

    result = finding_alerts.evaluate(
        con, now=NOW + timedelta(seconds=finding_alerts.DEBOUNCE_SECONDS + 120))
    assert result["raised"] == ["one tcp/9100 v4"]
    assert "was not reachable, now unreviewed" in all_alerts(con)[0]["detail"]


def test_a_shut_undeclared_port_appearing_raises_nothing(con):
    """The other half, and the reason `not reachable` is not alertable.

    A new host reports a port that is firewalled off and nobody has declared.
    Before the split that read `unreviewed`, which IS in `ALERTABLE_STATES`,
    so a port doing nothing wrong mailed a letter on the pass after it
    appeared. Now it reads `not reachable` and is recorded without one.
    """
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe(con, host_id, [("v4", 22, prober.STATE_NO_RESPONSE)])
    finding_alerts.evaluate(con, now=NOW)                      # baseline

    report(con, host_id, document(sockets=[socket_row(22), socket_row(9100)]))
    probe(con, host_id, [("v4", 22, prober.STATE_NO_RESPONSE),
                         ("v4", 9100, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T12:00:00+00:00")
    finding_alerts.evaluate(con, now=NOW + timedelta(minutes=1))
    result = finding_alerts.evaluate(
        con, now=NOW + timedelta(seconds=finding_alerts.DEBOUNCE_SECONDS + 120))

    assert result["raised"] == []
    assert "one tcp/9100 v4" in result["noted"]
    assert all_alerts(con) == []


# ================================ every vantage watched on its own, 2026-09-08
#
# With two boxes the newest pass of either is always fresh, so a watch reading
# only the newest run never notices a dead probe2 while probe1 keeps the screen
# current. Every test above this line runs with no registry and is the proof
# that the single-vantage behaviour did not move.

from app import vantages as vantage_registry  # noqa: E402

PROBE1_V4 = "78.141.210.130"
PROBE2_V4 = "185.199.110.7"


def registry(con, *names, off=()):
    vantage_registry.init(con)
    for n, name in enumerate(names):
        vantage_registry.add(con, name, f"root@{name}",
                             [f"185.199.110.{n + 1}"])
    for name in off:
        vantage_registry.set_enabled(con, name, False)


def probed_from(con, host_id, vantage, when):
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)],
          started_at=when.isoformat(), vantage=vantage)


def test_two_fresh_vantages_raise_nothing(con):
    host_id = add_host(con, "one")
    report(con, host_id, document(sockets=[socket_row(443)]))
    registry(con, "probe1", "probe2")
    probed_from(con, host_id, "probe1", NOW)
    probed_from(con, host_id, "probe2", NOW)
    result = finding_alerts.sweep_outside_views(con, now=NOW + timedelta(hours=1))
    assert result["stale"] == [] and result["stale_from"] == []


def test_a_dead_second_vantage_is_noticed_while_the_first_keeps_refreshing(con):
    """The reason this exists. probe1 measured a minute ago, probe2 has not
    finished a pass in five hours, and the newest run of the host is fresh."""
    host_id = add_host(con, "one")
    report(con, host_id, document(sockets=[socket_row(443)]))
    registry(con, "probe1", "probe2")
    later = NOW + timedelta(hours=5)
    probed_from(con, host_id, "probe2", NOW)
    probed_from(con, host_id, "probe1", later - timedelta(minutes=1))
    result = finding_alerts.sweep_outside_views(con, now=later)
    assert result["stale"] == ["one"]
    assert result["stale_from"] == [("one", "probe2")]
    raised = all_alerts(con, finding_alerts.KIND_OUTSIDE_STALE)
    assert len(raised) == 1
    assert "from probe2 in 5 hours" in raised[0]["detail"]
    assert "probe1" not in raised[0]["detail"]


def test_both_vantages_quiet_names_both(con):
    host_id = add_host(con, "one")
    report(con, host_id, document(sockets=[socket_row(443)]))
    registry(con, "probe1", "probe2")
    probed_from(con, host_id, "probe1", NOW)
    probed_from(con, host_id, "probe2", NOW - timedelta(hours=2))
    result = finding_alerts.sweep_outside_views(con, now=NOW + STALE)
    assert result["stale_from"] == [("one", "probe1"), ("one", "probe2")]
    detail = all_alerts(con, finding_alerts.KIND_OUTSIDE_STALE)[0]["detail"]
    assert "probe1 in 3 hours" in detail and "probe2 in 5 hours" in detail


def test_a_vantage_switched_off_is_not_watched(con):
    host_id = add_host(con, "one")
    report(con, host_id, document(sockets=[socket_row(443)]))
    registry(con, "probe1", "probe2", off=("probe2",))
    probed_from(con, host_id, "probe2", NOW - timedelta(days=3))
    probed_from(con, host_id, "probe1", NOW)
    result = finding_alerts.sweep_outside_views(con, now=NOW + timedelta(hours=1))
    assert result["stale"] == []


def test_a_vantage_that_never_probed_this_host_never_raises(con):
    """The same rule as a host never probed: refreshing that never started
    has not stopped. probe2 is registered and has no run for this host."""
    host_id = add_host(con, "one")
    report(con, host_id, document(sockets=[socket_row(443)]))
    registry(con, "probe1", "probe2")
    probed_from(con, host_id, "probe1", NOW)
    result = finding_alerts.sweep_outside_views(con, now=NOW + timedelta(hours=1))
    assert result["stale"] == [] and result["checked"] == 1


def test_the_alert_resolves_when_the_quiet_vantage_is_back(con):
    host_id = add_host(con, "one")
    report(con, host_id, document(sockets=[socket_row(443)]))
    registry(con, "probe1", "probe2")
    later = NOW + STALE
    probed_from(con, host_id, "probe2", NOW)
    probed_from(con, host_id, "probe1", later)
    assert finding_alerts.sweep_outside_views(con, now=later)["stale"] == ["one"]
    probed_from(con, host_id, "probe2", later + timedelta(minutes=1))
    result = finding_alerts.sweep_outside_views(con, now=later + timedelta(minutes=2))
    assert result["resolved"] == ["one"]


def test_runs_under_a_name_the_registry_does_not_know_are_still_watched(con):
    """A registry whose names do not match the stored runs must not switch the
    watch off. The newest run whoever took it is watched, as before."""
    host_id = add_host(con, "one")
    report(con, host_id, document(sockets=[socket_row(443)]))
    registry(con, "probe1")
    probed_from(con, host_id, "amsterdam-box", NOW)
    assert finding_alerts.sweep_outside_views(con, now=NOW + timedelta(hours=1))["stale"] == []
    result = finding_alerts.sweep_outside_views(con, now=NOW + STALE)
    assert result["stale"] == ["one"]
    assert result["stale_from"] == []
    detail = all_alerts(con, finding_alerts.KIND_OUTSIDE_STALE)[0]["detail"]
    assert detail.startswith("no probing pass has finished for one in 3 hours")


def test_a_run_from_a_registered_vantage_that_never_finished_does_not_count(con):
    host_id = add_host(con, "one")
    report(con, host_id, document(sockets=[socket_row(443)]))
    registry(con, "probe1", "probe2")
    probed_from(con, host_id, "probe1", NOW)
    probed_from(con, host_id, "probe2", NOW - timedelta(hours=4))
    con.execute("INSERT INTO probe_runs (host_id, vantage, started_at)"
                " VALUES (?, 'probe2', ?)", (host_id, NOW.isoformat()))
    con.commit()
    result = finding_alerts.sweep_outside_views(con, now=NOW + timedelta(hours=1))
    assert result["stale_from"] == [("one", "probe2")]


def test_with_one_registered_vantage_the_answer_is_the_old_answer(con):
    """The single-vantage behaviour, with the registry holding one row that
    matches the stored runs: the same host goes stale at the same moment
    with the same words as it did before the registry existed."""
    host_id = add_host(con, "one")
    report(con, host_id, document(sockets=[socket_row(443)]))
    registry(con, "probe1")
    probed_from(con, host_id, "probe1", NOW)
    assert finding_alerts.sweep_outside_views(
        con, now=NOW + STALE - timedelta(seconds=1))["stale"] == []
    result = finding_alerts.sweep_outside_views(con, now=NOW + STALE)
    assert result["stale"] == ["one"]
    assert result["stale_from"] == [("one", "probe1")]
    detail = all_alerts(con, finding_alerts.KIND_OUTSIDE_STALE)[0]["detail"]
    assert "for one from probe1 in 3 hours" in detail


def test_a_second_vantage_disagreeing_does_not_mail_on_its_own(con):
    """A port reachable from probe1 stays reachable when probe2 sees silence
    (`docs/PRODUCT.md` 8e). The mark is beside the state, so the state did not
    change and nothing here fires. Whether the mark itself should mail is a
    separate decision and is not taken here."""
    host_id = add_host(con, "one")
    report(con, host_id, document(sockets=[socket_row(443)]))
    probed_from(con, host_id, "probe1", NOW)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    before = len(all_alerts(con))
    probe(con, host_id, [("v4", 443, prober.STATE_NO_RESPONSE)],
          started_at=(NOW + timedelta(minutes=1)).isoformat(), vantage="probe2")
    finding_alerts.evaluate(con, now=NOW + timedelta(minutes=2))
    finding_alerts.evaluate(con, now=NOW + timedelta(minutes=2) + DEBOUNCE)
    assert len(all_alerts(con)) == before
    finding = [f for f in join.host_findings(con, host_id).findings
               if f.port == 443 and f.family == "v4"][0]
    assert finding.outside.disagree is True


# ============================== told once, asking nothing, 2026-09-27
#
# The owner's decision: `docs/PRODUCT.md` 8d decides whether a port needs an
# answer and 4c decides whether you are told. Measured on fart on 2026-09-26
# (`docs/RECORD.md` 4.200): a port opened with a listener and `ufw allow 3000`
# was probed within seven minutes, called `intended`, and never mailed, while
# the same port behind Docker with no rule was mailed 27 minutes in. These are
# the five cases he asked for, then the guards around them.

UFW_ALLOW_22 = "ip protocol tcp tcp dport 22 counter accept"
UFW_ALLOW_3000 = "ip protocol tcp tcp dport 3000 counter accept"
LATER = "2026-08-17T12:00:00+00:00"


def unit_socket(port, unit, family="v4", bind_address="0.0.0.0"):
    """A socket the way agent 0.1.10 sends it: the unit the kernel named and
    no process name (`docs/RECORD.md` 4.169)."""
    return {"protocol": "tcp", "family": family, "bind_address": bind_address,
            "port": port, "process_name": "", "unit": unit, "pid": None}


def ufw_table(family, rules):
    """`ufw_v4` for either family, `ip` or `ip6`."""
    table = ufw_v4(rules)
    table["family"] = family
    return table


def open_finding_alerts(con):
    return [row for row in all_alerts(con, finding_alerts.KIND_FINDING)
            if row["resolved_at"] is None]


def a_server_with_ssh(con):
    """fart before the test: 22 open behind its own ufw rule, measured once,
    so the next port has a history to be new against."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22, process="sshd")],
                                  tables=[ufw_v4([UFW_ALLOW_22])]))
    probe(con, host_id, [("v4", 22, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)
    return host_id


def port_3000_opened_with_ufw_allow(con, host_id):
    """Case A: a listener, then `ufw allow 3000`, then the probe."""
    report(con, host_id, document(
        sockets=[socket_row(22, process="sshd"),
                 unit_socket(3000, "porttest-a.service")],
        tables=[ufw_v4([UFW_ALLOW_22, UFW_ALLOW_3000])]))
    probe(con, host_id, [("v4", 22, prober.STATE_CONNECTED),
                         ("v4", 3000, prober.STATE_CONNECTED)], started_at=LATER)


def test_a_port_opened_with_ufw_allow_is_mailed_once(con):
    """Case A. The port is `intended`, your rule answered it, and it is told
    once: one mail, naming the port, the family, the program and the rule."""
    host_id = a_server_with_ssh(con)
    port_3000_opened_with_ufw_allow(con, host_id)

    held = finding_alerts.evaluate(con, now=NOW)
    assert held["holding"] == ["one tcp/3000 v4"]
    assert mailed(con) == []

    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    assert result["told"] == ["one tcp/3000 v4"]
    assert result["raised"] == []

    letters = mailed(con)
    assert len(letters) == 1
    subject, body, html = letters[0]
    assert subject == "[whichports] Port 3000 on one became reachable from the internet"
    assert ("  server: one\n  port: 3000\n"
            "  allowed by: a rule in the server's firewall\n"
            "  program: porttest-a\n") in body
    # Which firewall is said. The rule's own text stays on the server's page.
    assert UFW_ALLOW_3000 not in body
    assert "became reachable from the internet" in visible_text(html)
    assert "porttest-a" in visible_text(html)


def test_the_port_told_about_stays_your_rule_and_nothing_waits(con):
    """Nothing asks for a click: the state stays `intended`, the notice is
    resolved from the moment it exists, so no list of open alerts, no count
    and no header can carry it."""
    host_id = a_server_with_ssh(con)
    port_3000_opened_with_ufw_allow(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    row = [r for r in states(con) if r["port"] == 3000][0]
    assert row["state"] == join.STATE_INTENDED
    assert open_finding_alerts(con) == []
    notice = all_alerts(con, finding_alerts.KIND_FINDING)[0]
    assert notice["resolved_at"] == notice["raised_at"]
    # The dead-man's queue reads open alerts only, so the notice is the
    # finding queue's alone and cannot be sent twice by two readers.
    assert alerts.pending_notifications(con) == []


def test_the_port_told_about_is_never_told_again(con):
    host_id = a_server_with_ssh(con)
    port_3000_opened_with_ufw_allow(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    for alert_id, _ in finding_alerts.pending_deliveries(con, now=NOW + DEBOUNCE)[0][1]:
        alerts.mark_notified(con, alert_id, NOW + DEBOUNCE)

    for minute in range(20, 6 * 60, 5):
        finding_alerts.evaluate(con, now=NOW + timedelta(minutes=minute))
    assert finding_alerts.pending_deliveries(con, now=NOW + timedelta(hours=6)) == []
    assert len(all_alerts(con, finding_alerts.KIND_FINDING)) == 1


def test_a_docker_port_with_no_rule_is_mailed_as_it_was(con):
    """Case A2. Unchanged: `unreviewed`, an open alert that waits for an
    answer, and one mail. The only new fact on the change is the program,
    which is the container and never `docker.service`."""
    host_id = a_server_with_ssh(con)
    doc = document(sockets=[socket_row(22, process="sshd"),
                            unit_socket(3001, "docker.service")],
                   tables=[ufw_v4([UFW_ALLOW_22])])
    doc["containers"] = {"status": "collected", "docker": [
        {"name": "porttest-c", "ports": [
            {"host_ip": "0.0.0.0", "host_port": 3001, "container_port": 3001,
             "protocol": "tcp"}]}]}
    report(con, host_id, doc)
    probe(con, host_id, [("v4", 22, prober.STATE_CONNECTED),
                         ("v4", 3001, prober.STATE_CONNECTED)], started_at=LATER)
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    assert result["raised"] == ["one tcp/3001 v4"]
    assert result["told"] == []
    assert [row["subject"] for row in open_finding_alerts(con)] == ["tcp/3001 v4"]
    letters = mailed(con)
    assert len(letters) == 1
    assert letters[0][0] == "[whichports] Port 3001 on one is reachable from the internet"
    assert ("  port: 3001\n  you said: nothing yet\n"
            "  program: container porttest-c\n") in letters[0][1]
    # A container's port names no rule: the engine does not walk the path
    # a published port takes.
    assert "allowed by" not in letters[0][1]
    assert changes(con)[-1]["program"] == "container porttest-c"


def test_a_new_servers_first_measurement_mails_nothing(con):
    """Three ports a rule answers, both families, measured for the first time.
    A starting point, not three transitions, however long it is watched."""
    host_id = add_host(con)
    ports = (22, 80, 443)
    report(con, host_id, document(
        sockets=[socket_row(p) for p in ports]
        + [socket_row(p, family="v6", bind_address="::") for p in ports],
        tables=[ufw_table("ip", [f"ip protocol tcp tcp dport {p} counter accept"
                                 for p in ports]),
                ufw_table("ip6", [f"meta l4proto tcp tcp dport {p} counter accept"
                                  for p in ports])]))
    probe(con, host_id, [(fam, p, prober.STATE_CONNECTED)
                         for fam in ("v4", "v6") for p in ports])

    first = finding_alerts.evaluate(con, now=NOW)
    assert first["baselines"] == 6
    assert {row["state"] for row in states(con)} == {join.STATE_INTENDED}
    for minute in range(5, 3 * 60, 5):
        finding_alerts.evaluate(con, now=NOW + timedelta(minutes=minute))

    assert all_alerts(con) == []
    assert changes(con) == []
    assert mailed(con) == []


def a_server_measured_on_v4_only(con, ports=(22, 80)):
    """A dual-stack server whose agent proved v4 first. Its v6 address is
    proved later, which is every dual-stack server today (RECORD 4.184)."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(p) for p in ports]
        + [socket_row(p, family="v6", bind_address="::") for p in ports],
        tables=[ufw_table("ip", [f"ip protocol tcp tcp dport {p} counter accept"
                                 for p in ports]),
                ufw_table("ip6", [f"meta l4proto tcp tcp dport {p} counter accept"
                                  for p in ports])]))
    probe(con, host_id, [("v4", p, prober.STATE_CONNECTED) for p in ports])
    finding_alerts.evaluate(con, now=NOW)
    return host_id


def test_a_family_measured_later_is_a_first_measurement_too(con):
    """The burst this rule exists to stop. v6 measured for the first time
    eight hours after v4, as fart's was on 2026-08-28: every port a rule
    answers would otherwise read as having just become reachable."""
    host_id = a_server_measured_on_v4_only(con)
    probe(con, host_id, [(fam, p, prober.STATE_CONNECTED)
                         for fam in ("v4", "v6") for p in (22, 80)],
          started_at=LATER)
    later = NOW + timedelta(hours=8)
    result = finding_alerts.evaluate(con, now=later)
    finding_alerts.evaluate(con, now=later + DEBOUNCE)

    assert result["baselines"] == 2
    assert all_alerts(con) == []
    assert changes(con) == []
    assert mailed(con) == []


def test_a_late_familys_unreviewed_port_is_a_starting_point_as_well(con):
    """The cost, pinned so nobody finds it by surprise. Before 2026-09-27 a
    port with no rule, reachable on a family measured late, mailed: fart's
    tcp/22 on v6 did on 2026-08-28. Now a late family is a first measurement
    like a new server's, and it is on the screen and not in a mail."""
    host_id = a_server_measured_on_v4_only(con, ports=(22,))
    report(con, host_id, document(
        sockets=[socket_row(22), socket_row(22, family="v6", bind_address="::")],
        tables=[ufw_table("ip", [UFW_ALLOW_22])]))
    probe(con, host_id, [("v4", 22, prober.STATE_CONNECTED),
                         ("v6", 22, prober.STATE_CONNECTED)], started_at=LATER)
    finding_alerts.evaluate(con, now=NOW + timedelta(hours=8))
    finding_alerts.evaluate(con, now=NOW + timedelta(hours=8) + DEBOUNCE)

    v6 = [r for r in states(con) if r["family"] == "v6"][0]
    assert v6["state"] == join.STATE_UNREVIEWED
    assert all_alerts(con) == []


def test_after_its_first_measurement_a_new_port_in_that_family_is_told(con):
    """The late family has a history once it has been measured, so the next
    port that opens on it is news."""
    host_id = a_server_measured_on_v4_only(con)
    probe(con, host_id, [(fam, p, prober.STATE_CONNECTED)
                         for fam in ("v4", "v6") for p in (22, 80)],
          started_at=LATER)
    finding_alerts.evaluate(con, now=NOW + timedelta(hours=8))

    report(con, host_id, document(
        sockets=[socket_row(p) for p in (22, 80)]
        + [socket_row(p, family="v6", bind_address="::") for p in (22, 80, 3000)],
        tables=[ufw_table("ip", [UFW_ALLOW_22]),
                ufw_table("ip6", [f"meta l4proto tcp tcp dport {p} counter accept"
                                  for p in (22, 80, 3000)])]))
    probe(con, host_id, [("v6", 3000, prober.STATE_CONNECTED)],
          started_at="2026-08-17T21:00:00+00:00")
    later = NOW + timedelta(hours=9)
    finding_alerts.evaluate(con, now=later)
    result = finding_alerts.evaluate(con, now=later + DEBOUNCE)

    assert result["told"] == ["one tcp/3000 v6"]


def test_a_port_that_opens_and_shuts_inside_the_window_mails_nothing(con):
    """4c's debounce, unchanged for the new mail: written to history, never
    mailed."""
    host_id = a_server_with_ssh(con)
    port_3000_opened_with_ufw_allow(con, host_id)
    finding_alerts.evaluate(con, now=NOW)

    report(con, host_id, document(sockets=[socket_row(22, process="sshd")],
                                  tables=[ufw_v4([UFW_ALLOW_22])]))
    probe(con, host_id, [("v4", 22, prober.STATE_CONNECTED),
                         ("v4", 3000, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T12:05:00+00:00")
    result = finding_alerts.evaluate(con, now=NOW + timedelta(minutes=5))
    for minute in range(10, 120, 5):
        finding_alerts.evaluate(con, now=NOW + timedelta(minutes=minute))

    assert result["reverted"] == ["one tcp/3000 v4"]
    assert all_alerts(con) == []
    assert mailed(con) == []
    assert [row["outcome"] for row in changes(con)] == [finding_alerts.OUTCOME_REVERTED]


def test_a_port_you_said_yes_to_before_it_opened_is_told_with_your_yes(con):
    """No rule, a declaration made before anything listened. It became
    reachable all the same, and the answer the mail names is yours."""
    host_id = a_server_with_ssh(con)
    intent.declare(con, "one", "tcp", 8080, "v4", "open")
    report(con, host_id, document(
        sockets=[socket_row(22, process="sshd"), socket_row(8080, process="grafana")],
        tables=[ufw_v4([UFW_ALLOW_22])]))
    probe(con, host_id, [("v4", 22, prober.STATE_CONNECTED),
                         ("v4", 8080, prober.STATE_CONNECTED)], started_at=LATER)
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    assert result["told"] == ["one tcp/8080 v4"]
    _, body, _html = mailed(con)[0]
    assert "  allowed by: your yes\n  program: grafana\n" in body
    assert "a rule in" not in body


def test_a_rule_port_measured_shut_and_then_answering_is_told(con):
    """`not reachable` to `intended`: the listener was there and something in
    the path stopped it, then it answered. That is a port becoming reachable
    and it is said once."""
    host_id = a_server_with_ssh(con)
    report(con, host_id, document(
        sockets=[socket_row(22, process="sshd"), unit_socket(3000, "porttest-a.service")],
        tables=[ufw_v4([UFW_ALLOW_22, UFW_ALLOW_3000])]))
    probe(con, host_id, [("v4", 3000, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T11:40:00+00:00")
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    assert mailed(con) == []

    probe(con, host_id, [("v4", 3000, prober.STATE_CONNECTED)],
          started_at="2026-08-17T13:00:00+00:00")
    later = NOW + timedelta(hours=1)
    finding_alerts.evaluate(con, now=later)
    result = finding_alerts.evaluate(con, now=later + DEBOUNCE)

    assert result["told"] == ["one tcp/3000 v4"]
    assert "was not reachable, now intended" in all_alerts(con)[-1]["detail"]


def test_a_port_you_said_no_to_that_stays_shut_is_not_told(con):
    """`intended` without a connect: a port declared closed and measured
    silent. Nothing became reachable."""
    host_id = a_server_with_ssh(con)
    intent.declare(con, "one", "tcp", 5432, "v4", "closed")
    report(con, host_id, document(
        sockets=[socket_row(22, process="sshd"), socket_row(5432, process="postgres")],
        tables=[ufw_v4([UFW_ALLOW_22])]))
    probe(con, host_id, [("v4", 22, prober.STATE_CONNECTED),
                         ("v4", 5432, prober.STATE_NO_RESPONSE)], started_at=LATER)
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    assert result["noted"] == ["one tcp/5432 v4"]
    assert result["told"] == []
    assert mailed(con) == []


def test_a_rule_added_to_a_port_already_answering_is_not_told(con):
    """`unreviewed` to `intended`: the port was reachable already and got an
    answer. That closes its open alert and is not a port becoming reachable."""
    host_id = a_server_with_ssh(con)
    report(con, host_id, document(
        sockets=[socket_row(22, process="sshd"), unit_socket(3000, "porttest-a.service")],
        tables=[ufw_v4([UFW_ALLOW_22])]))
    probe(con, host_id, [("v4", 3000, prober.STATE_CONNECTED)], started_at=LATER)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    assert len(open_finding_alerts(con)) == 1

    report(con, host_id, document(
        sockets=[socket_row(22, process="sshd"), unit_socket(3000, "porttest-a.service")],
        tables=[ufw_v4([UFW_ALLOW_22, UFW_ALLOW_3000])]))
    later = NOW + timedelta(hours=1)
    finding_alerts.evaluate(con, now=later)
    result = finding_alerts.evaluate(con, now=later + DEBOUNCE)

    assert result["noted"] == ["one tcp/3000 v4"]
    assert result["told"] == []
    assert open_finding_alerts(con) == []


def test_a_muted_server_is_not_told(con):
    host_id = a_server_with_ssh(con)
    finding_alerts.mute_host(con, "one", now=NOW)
    port_3000_opened_with_ufw_allow(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    assert result["suppressed"] == ["one tcp/3000 v4"]
    assert result["told"] == []
    assert mailed(con) == []


def test_a_silenced_port_is_not_told(con):
    host_id = a_server_with_ssh(con)
    finding_alerts.silence_port(con, "one", "tcp", 3000, "v4", now=NOW)
    port_3000_opened_with_ufw_allow(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    assert mailed(con) == []


def test_a_rate_limit_explains_a_rule_port_coming_back():
    """A rule port behind a rate limit answers and goes silent by itself, so
    `not reachable` to `intended` is a flap there and not news."""
    from types import SimpleNamespace
    limited = SimpleNamespace(rate_limited=True)
    plain = SimpleNamespace(rate_limited=False)
    assert finding_alerts.rate_limit_flap(
        limited, join.STATE_NOT_REACHABLE, join.STATE_INTENDED)
    assert not finding_alerts.rate_limit_flap(
        plain, join.STATE_NOT_REACHABLE, join.STATE_INTENDED)
    # A brand new port has no flap to explain.
    assert not finding_alerts.rate_limit_flap(limited, "", join.STATE_INTENDED)


def test_became_reachable_needs_all_three_halves():
    from types import SimpleNamespace
    connected = SimpleNamespace(outside=SimpleNamespace(connected=True))
    silent = SimpleNamespace(outside=SimpleNamespace(connected=False))
    yes = finding_alerts.became_reachable
    for before in ("", join.STATE_NOT_REACHABLE, join.STATE_STALE_RULE):
        assert yes(connected, before, join.STATE_INTENDED)
        assert not yes(silent, before, join.STATE_INTENDED)
    for before in (join.STATE_UNREVIEWED, join.STATE_UNEXPLAINED,
                   join.STATE_CONFLICT, join.STATE_INTENDED):
        assert not yes(connected, before, join.STATE_INTENDED)
    assert not yes(connected, "", join.STATE_UNREVIEWED)


def test_a_notice_and_an_alert_on_one_server_leave_in_one_mail(con):
    """4c's coalescing covers the new mail: a port told about and a port that
    asks for an answer, confirmed on the same pass, are one letter."""
    host_id = a_server_with_ssh(con)
    report(con, host_id, document(
        sockets=[socket_row(22, process="sshd"), unit_socket(3000, "porttest-a.service"),
                 socket_row(9100, process="node_exporter")],
        tables=[ufw_v4([UFW_ALLOW_22, UFW_ALLOW_3000])]))
    probe(con, host_id, [("v4", 22, prober.STATE_CONNECTED),
                         ("v4", 3000, prober.STATE_CONNECTED),
                         ("v4", 9100, prober.STATE_CONNECTED)], started_at=LATER)
    finding_alerts.evaluate(con, now=NOW)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    assert result["told"] == ["one tcp/3000 v4"]
    assert result["raised"] == ["one tcp/9100 v4"]
    letters = mailed(con)
    assert len(letters) == 1
    subject, body, _html = letters[0]
    assert subject == "[whichports] 2 ports changed on one"
    assert "  reachable: 3000, 9100\n" in body


def test_a_notice_older_than_a_day_is_history_and_not_sent(con):
    """A channel added today is not sent every notice ever recorded."""
    host_id = a_server_with_ssh(con)
    port_3000_opened_with_ufw_allow(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    kept = timedelta(seconds=finding_alerts.NOTICE_KEPT_SECONDS)
    assert finding_alerts.pending_deliveries(con, now=NOW + DEBOUNCE + kept)
    assert finding_alerts.pending_deliveries(
        con, now=NOW + DEBOUNCE + kept + timedelta(seconds=1)) == []
    assert finding_alerts.pending_deliveries(
        con, channel="webhook:NEW", now=NOW + timedelta(days=2)) == []


def test_a_notice_whose_port_shut_again_before_it_was_sent_is_not_sent(con):
    """The relay was down while the port became reachable and then shut. The
    mail would say reachable about a port that is not, so it is not sent."""
    host_id = a_server_with_ssh(con)
    port_3000_opened_with_ufw_allow(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)

    report(con, host_id, document(sockets=[socket_row(22, process="sshd")],
                                  tables=[ufw_v4([UFW_ALLOW_22])]))
    probe(con, host_id, [("v4", 3000, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T12:30:00+00:00")
    later = NOW + timedelta(minutes=30)
    finding_alerts.evaluate(con, now=later)
    assert finding_alerts.pending_deliveries(con, now=later)   # still pending
    finding_alerts.evaluate(con, now=later + DEBOUNCE)

    assert finding_alerts.pending_deliveries(con, now=later + DEBOUNCE) == []


def test_the_notice_letter_keeps_the_writing_rules(con):
    """The writing rules over the new lines, both halves."""
    host_id = a_server_with_ssh(con)
    port_3000_opened_with_ufw_allow(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    texts = every_letter(con)
    assert texts
    for text in texts:
        lowered = text.lower()
        for word in BANNED:
            assert word not in lowered, f"{word!r} in {text!r}"
        for phrase in POSTURE:
            assert phrase not in lowered, f"{phrase!r} in {text!r}"
        assert "—" not in text and "–" not in text
        assert ";" not in text


def test_program_of_names_the_container_and_the_unit_without_its_suffix():
    from types import SimpleNamespace
    sock = join.ListeningSocket
    pub = join.Publication
    def finding(sockets=(), publications=()):
        return SimpleNamespace(inside=SimpleNamespace(sockets=sockets,
                                                      publications=publications))
    assert finding_alerts.program_of(finding(
        [sock("", "0.0.0.0", None, unit="porttest-a.service")])) == "porttest-a"
    assert finding_alerts.program_of(finding(
        [sock("python3", "0.0.0.0", 7, unit="porttest-a.service")])) == "python3"
    assert finding_alerts.program_of(finding(
        [sock("", "0.0.0.0", None, unit="docker.service")],
        [pub("docker", "porttest-c", "0.0.0.0", "v4")])) == "container porttest-c"
    # Named by nothing but its user: no program line rather than a guess.
    assert finding_alerts.program_of(finding(
        [sock("", "0.0.0.0", None, unit="session-4.scope", owner_name="root")])) == ""
    assert finding_alerts.program_of(finding(
        [sock("", "0.0.0.0", None, unit="docker.service")])) == ""


# ================================ a different program on an answered port
#
# Case B of 2026-09-26: tcp/3000 was said yes to while python3 served it,
# then perl took it over, and nothing was said anywhere. The owner, 2026-09-27:
# told once, naming the old program and the new one, and the answer stays.

def port_3000_served_by(con, host_id, unit, started_at, *, rule=False,
                        socket=None):
    tables = [ufw_v4([UFW_ALLOW_22] + ([UFW_ALLOW_3000] if rule else []))]
    report(con, host_id, document(
        sockets=[socket_row(22, process="sshd"),
                 socket or unit_socket(3000, unit)], tables=tables))
    probe(con, host_id, [("v4", 22, prober.STATE_CONNECTED),
                         ("v4", 3000, prober.STATE_CONNECTED)],
          started_at=started_at)


def an_answered_port(con, *, rule=False, unit="porttest-a.service", socket=None):
    """3000 served and answered, settled, before anything is swapped."""
    host_id = a_server_with_ssh(con)
    if not rule:
        intent.declare(con, "one", "tcp", 3000, "v4", "open")
    port_3000_served_by(con, host_id, unit, LATER, rule=rule, socket=socket)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    for alert_id, _ in [i for _, items in finding_alerts.pending_deliveries(
            con, now=NOW) for i in items]:
        alerts.mark_notified(con, alert_id, NOW + DEBOUNCE)
    return host_id


def swap(con, host_id, unit="porttest-b.service", *, rule=False, socket=None,
         hours=1):
    later = NOW + timedelta(hours=hours)
    port_3000_served_by(con, host_id, unit, later.isoformat(), rule=rule,
                        socket=socket)
    first = finding_alerts.evaluate(con, now=later)
    settled = finding_alerts.evaluate(con, now=later + DEBOUNCE)
    return first, settled


def test_a_different_program_behind_your_yes_is_mailed_once(con):
    """Case B. The yes stays, the state stays, one mail names both."""
    host_id = an_answered_port(con)
    first, settled = swap(con, host_id)

    assert first["holding"] == ["one tcp/3000 v4"]
    assert settled["new_program"] == ["one tcp/3000 v4"]
    letters = mailed(con)
    assert len(letters) == 1
    _, body, html = letters[0]
    assert body.startswith("A different program answers port 3000 on one\n")
    assert ("  program: porttest-b\n  before: porttest-a\n"
            "  your yes: stays\n") in body
    seen = visible_text(html)
    assert "A different program answers port 3000 on one" in seen
    assert "porttest-b" in seen and "porttest-a" in seen

    row = [r for r in states(con) if r["port"] == 3000][0]
    assert row["state"] == join.STATE_INTENDED
    assert intent.intents_for_host(con, host_id)[("tcp", 3000, "v4")] == "open"
    assert open_finding_alerts(con) == []


def test_a_different_program_behind_your_rule_is_mailed_once(con):
    host_id = an_answered_port(con, rule=True)
    _, settled = swap(con, host_id, rule=True)

    assert settled["new_program"] == ["one tcp/3000 v4"]
    _, body, _html = mailed(con)[0]
    assert ("  before: porttest-a\n"
            "  allowed by: a rule in the server's firewall\n") in body
    assert "your yes" not in body
    assert UFW_ALLOW_3000 not in body


def test_the_new_program_is_told_about_once(con):
    host_id = an_answered_port(con)
    swap(con, host_id)
    for alert_id, _ in [i for _, items in finding_alerts.pending_deliveries(
            con, now=NOW) for i in items]:
        alerts.mark_notified(con, alert_id, NOW + timedelta(hours=2))
    for minute in range(90, 8 * 60, 5):
        finding_alerts.evaluate(con, now=NOW + timedelta(minutes=minute))
    assert mailed(con) == []


def test_a_program_that_comes_back_inside_the_window_mails_nothing(con):
    """A restart that briefly showed another unit. 4c's debounce, for the
    program as for the state."""
    host_id = an_answered_port(con)
    later = NOW + timedelta(hours=1)
    port_3000_served_by(con, host_id, "porttest-b.service", later.isoformat())
    finding_alerts.evaluate(con, now=later)
    port_3000_served_by(con, host_id, "porttest-a.service",
                        (later + timedelta(minutes=5)).isoformat())
    back = finding_alerts.evaluate(con, now=later + timedelta(minutes=5))
    finding_alerts.evaluate(con, now=later + DEBOUNCE + timedelta(minutes=5))

    assert back["reverted"] == ["one tcp/3000 v4"]
    assert mailed(con) == []


def test_an_agent_upgrade_that_names_units_instead_of_processes_mails_nothing(con):
    """0.1.8 sent process names and 0.1.10 sends units (record 4.169). The
    same program, named another way, on every answered port of a server."""
    host_id = an_answered_port(con, socket=socket_row(3000, process="python3"))
    _, settled = swap(con, host_id, "porttest-a.service")

    assert settled["new_program"] == []
    assert mailed(con) == []
    row = [r for r in states(con) if r["port"] == 3000][0]
    assert row["program"] == "unit:porttest-a.service"


@pytest.mark.parametrize("unit", ["session-4.scope", "run-19945.service",
                                  "run-u123.service"])
def test_a_unit_that_changes_on_every_start_is_never_compared(con, unit):
    """A login session's scope and a name systemd-run made up change when
    nothing but a restart happened."""
    host_id = an_answered_port(con, unit=unit)
    _, settled = swap(con, host_id, unit.replace("4", "7").replace("1", "2"))
    assert settled["new_program"] == []
    assert mailed(con) == []


def test_a_port_that_asks_for_an_answer_is_not_told_about_its_program(con):
    """`unreviewed` is on the list already. Its program changing adds
    nothing to what it asks."""
    host_id = a_server_with_ssh(con)
    port_3000_served_by(con, host_id, "porttest-a.service", LATER)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    before = len(all_alerts(con))

    _, settled = swap(con, host_id)
    assert settled["new_program"] == []
    assert len(all_alerts(con)) == before


def test_a_container_replaced_by_another_is_told_by_container_name(con):
    host_id = a_server_with_ssh(con)
    intent.declare(con, "one", "tcp", 3001, "v4", "open")

    def served_by(container, started_at):
        doc = document(sockets=[socket_row(22, process="sshd"),
                                unit_socket(3001, "docker.service")],
                       tables=[ufw_v4([UFW_ALLOW_22])])
        doc["containers"] = {"status": "collected", "docker": [
            {"name": container, "ports": [
                {"host_ip": "0.0.0.0", "host_port": 3001, "container_port": 80,
                 "protocol": "tcp"}]}]}
        report(con, host_id, doc)
        probe(con, host_id, [("v4", 22, prober.STATE_CONNECTED),
                             ("v4", 3001, prober.STATE_CONNECTED)],
              started_at=started_at)

    served_by("grafana", LATER)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    for alert_id, _ in [i for _, items in finding_alerts.pending_deliveries(
            con, now=NOW) for i in items]:
        alerts.mark_notified(con, alert_id, NOW + DEBOUNCE)

    later = NOW + timedelta(hours=1)
    served_by("metabase", later.isoformat())
    finding_alerts.evaluate(con, now=later)
    finding_alerts.evaluate(con, now=later + DEBOUNCE)

    _, body, _html = mailed(con)[0]
    assert "  program: container metabase\n  before: container grafana\n" in body
    assert "docker.service" not in body


def test_a_v4_port_served_on_the_v6_wildcard_is_compared_by_its_unit(con):
    """Most services bind `::` and take v4 through it. The v4 half is named
    from that socket, not left as an unnamed process (record 4.200)."""
    def wildcard(unit):
        return unit_socket(3000, unit, family="v6", bind_address="::")
    host_id = an_answered_port(con, socket=wildcard("porttest-a.service"))
    _, settled = swap(con, host_id, socket=wildcard("porttest-b.service"))

    assert settled["new_program"] == ["one tcp/3000 v4"]
    _, body, _html = mailed(con)[0]
    assert "  program: porttest-b\n  before: porttest-a\n" in body


def test_rows_from_before_the_program_was_kept_mail_nothing_on_deploy(con):
    """Every row on the box has no program on the morning this deploys. The
    first pass after it learns the program and compares nothing."""
    host_id = an_answered_port(con)
    con.execute("UPDATE finding_states SET program = NULL")
    con.commit()
    _, settled = swap(con, host_id)

    assert settled["new_program"] == []
    assert mailed(con) == []
    row = [r for r in states(con) if r["port"] == 3000][0]
    assert row["program"] == "unit:porttest-b.service"


def test_a_muted_server_is_not_told_about_a_new_program(con):
    host_id = an_answered_port(con)
    finding_alerts.mute_host(con, "one", now=NOW + timedelta(minutes=50))
    _, settled = swap(con, host_id)
    assert settled["suppressed"] == ["one tcp/3000 v4"]
    assert mailed(con) == []


def test_a_state_change_overtakes_a_program_change_being_held(con):
    """The new program shuts the port before its window elapsed: the state
    change is the news, and the held change of program never happened."""
    host_id = an_answered_port(con)
    later = NOW + timedelta(hours=1)
    port_3000_served_by(con, host_id, "porttest-b.service", later.isoformat())
    finding_alerts.evaluate(con, now=later)
    probe(con, host_id, [("v4", 3000, prober.STATE_NO_RESPONSE)],
          started_at=(later + timedelta(minutes=5)).isoformat())
    result = finding_alerts.evaluate(con, now=later + timedelta(minutes=5))

    assert result["superseded"] == ["one tcp/3000 v4"]
    kinds = [(r["from_state"], r["to_state"], r["outcome"]) for r in changes(con)
             if r["port"] == 3000]
    assert kinds[-2][2] == finding_alerts.OUTCOME_SUPERSEDED
    assert kinds[-1][:2] == (join.STATE_INTENDED, join.STATE_CONFLICT)


def test_the_new_program_letter_keeps_the_writing_rules(con):
    host_id = an_answered_port(con)
    swap(con, host_id)
    texts = every_letter(con)
    assert texts
    for text in texts:
        lowered = text.lower()
        for word in BANNED:
            assert word not in lowered, f"{word!r} in {text!r}"
        assert "—" not in text and "–" not in text and ";" not in text


def test_program_keys_compare_like_with_like():
    assert finding_alerts.comparable("unit:a.service", "unit:b.service")
    assert finding_alerts.comparable("container:a", "unit:b.service")
    assert finding_alerts.comparable("process:perl", "container:b")
    assert not finding_alerts.comparable("process:python3", "unit:a.service")
    assert not finding_alerts.comparable("", "unit:a.service")
    assert finding_alerts.program_name("unit:porttest-a.service") == "porttest-a"
    assert finding_alerts.program_name("container:a,b") == "container a, container b"
    assert finding_alerts.program_name("process:perl") == "perl"


# ================================= what a message says, frozen with the change
#
# docs/screens/mails/SPEC-alert-messages.md. A message is built from values
# frozen when the change was first seen, and from nothing worked out when it
# is sent (rule 3.4). These tests hold the freezing. What the message then
# says is held in tests/test_alert_words.py.

def a_finding(state=join.STATE_CONFLICT, *, connected=True,
              host_rules=("tcp dport 443 accept",), provider_rules=(),
              nftables="collected", owns=True, containers=(), sockets=(),
              outside_source=False, measured=True, family="v4", port=443):
    """A finding with only the parts the freezing reads, so each branch can
    be named without building a fleet for it."""
    return SimpleNamespace(
        protocol="tcp", port=port, family=family, state=state,
        outside=SimpleNamespace(connected=connected, measured=measured),
        provider=SimpleNamespace(rules=tuple(provider_rules)),
        inside=SimpleNamespace(
            owns_the_port=owns, permit_rules=tuple(host_rules),
            nftables_status=nftables,
            publications=tuple(SimpleNamespace(container=name) for name in containers),
            sockets=tuple(SimpleNamespace(process_name=process, unit=unit)
                          for process, unit in sockets)),
        answered_outside_the_rules_source=outside_source)


def test_allowed_by_is_written_only_for_a_port_that_answers():
    for state in (join.STATE_CONFLICT, join.STATE_INTENDED):
        assert finding_alerts.allowed_by(a_finding(state)) == join.LAYER_HOST_FIREWALL
        # The provider's firewall is the outer one, and is named when both
        # hold a permit, as the engine does.
        for host_rules in ((), ("tcp dport 443 accept",)):
            assert finding_alerts.allowed_by(a_finding(
                state, host_rules=host_rules, provider_rules=("in tcp 443",))) == (
                join.LAYER_PROVIDER)
        # The same finding with the outside view not connected: the engine
        # does not say what dropped a packet, so nothing is kept.
        assert finding_alerts.allowed_by(a_finding(state, connected=False)) == ""
        assert finding_alerts.allowed_by(a_finding(
            state, connected=False, provider_rules=("in tcp 443",))) == ""


def test_a_conflict_with_no_permitting_rule_keeps_no_layer():
    assert finding_alerts.allowed_by(a_finding(host_rules=())) == ""
    # A ruleset that was not read holds no rule anyone can be said to have
    # written for this port.
    assert finding_alerts.allowed_by(a_finding(nftables="permission_denied")) == ""


def test_allowed_by_is_empty_for_unexplained_and_for_a_published_port():
    for state in (join.STATE_UNEXPLAINED, join.STATE_UNREVIEWED,
                  join.STATE_STALE_RULE, join.STATE_NOT_REACHABLE, None):
        assert finding_alerts.allowed_by(a_finding(state)) == "", state
    # A container's port: the engine does not walk the forward hook, so a
    # rule it found on input is one the packet may never meet.
    assert finding_alerts.allowed_by(a_finding(containers=("web",))) == ""
    # A port the server does not own, a server with no agent among them.
    assert finding_alerts.allowed_by(a_finding(
        owns=False, provider_rules=("in tcp 443",))) == ""


def test_what_is_said_of_the_program_is_worked_out_from_names_still_apart():
    said = finding_alerts.said_program
    assert said(a_finding(containers=("web",))) == "container web"
    assert said(a_finding(containers=("web", "db_1"))) == "container db_1, container web"
    assert said(a_finding(containers=("app.v2",))) == ""
    assert said(a_finding(sockets=(("caddy", None),))) == "caddy"
    assert said(a_finding(sockets=(("", "nginx.service"),))) == "nginx"
    assert said(a_finding(sockets=(("python3.12", None),))) == ""
    # A process that calls itself a container is one name with a space in
    # it. The page shows it as it is, and a message does not say it.
    spoof = a_finding(sockets=(("container web", None),))
    assert finding_alerts.program_of(spoof) == "container web"
    assert said(spoof) == ""
    assert said(a_finding()) == ""
    # The program before, from the key the port was last confirmed with.
    before = finding_alerts.said_program_of_key
    assert before("container:web,db_1") == "container web, container db_1"
    assert before("unit:nginx.service") == "nginx"
    assert before("unit:nginx.service,my_unit.service") == ""
    assert before("process:caddy") == "caddy"
    # Process names are joined with a comma in the key and a process may
    # hold one, so a key with a comma cannot be taken apart and says nothing.
    assert before("process:a,b") == ""
    assert before("") == "" and before(None) == "" and before("other:x") == ""


def test_the_other_familys_answer_is_worked_out_from_the_same_pass():
    this = a_finding(connected=False, family="v4")
    other = finding_alerts.other_family
    assert other(this, [this]) == ""
    assert other(this, [this, a_finding(family="v6")]) == alertwords.OTHER_ANSWERS
    assert other(this, [this, a_finding(family="v6", connected=False)]) == (
        alertwords.OTHER_DOES_NOT_ANSWER)
    assert other(this, [this, a_finding(family="v6", measured=False, connected=False)]) == (
        alertwords.OTHER_NOT_MEASURED)
    # Another port's v6 says nothing about this port.
    assert other(this, [this, a_finding(family="v6", port=80)]) == ""


def both_families(con, host_id, port=443):
    """One port listening in both families, declared open in both, measured
    answering in both on the first pass."""
    report(con, host_id, document(sockets=[
        socket_row(port, family="v4"),
        socket_row(port, family="v6", bind_address="::")]))
    for family in ("v4", "v6"):
        intent.declare(con, "one", "tcp", port, family, "open")
    probe(con, host_id, [("v4", port, prober.STATE_CONNECTED),
                         ("v6", port, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)


def test_the_other_familys_answer_is_frozen_with_the_change(con):
    host_id = add_host(con)
    both_families(con, host_id)
    probe(con, host_id, [("v4", 443, prober.STATE_NO_RESPONSE),
                         ("v6", 443, prober.STATE_CONNECTED)],
          started_at="2026-08-17T12:00:00+00:00")
    finding_alerts.evaluate(con, now=NOW)
    row = changes(con)[-1]
    assert (row["family"], row["other_family"]) == ("v4", alertwords.OTHER_ANSWERS)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    # The other family stops later. The message about v4 is not rewritten.
    probe(con, host_id, [("v4", 443, prober.STATE_NO_RESPONSE),
                         ("v6", 443, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T12:20:00+00:00")
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE + timedelta(minutes=5))
    first = [r for r in changes(con) if r["family"] == "v4"][-1]
    assert first["other_family"] == alertwords.OTHER_ANSWERS
    (_, items), = finding_alerts.pending_deliveries(con, now=NOW + DEBOUNCE)
    change = items[0][1]
    assert (change.port, change.protocol, change.family) == (443, "tcp", "v4")
    assert change.answers is False
    assert change.other_family == alertwords.OTHER_ANSWERS
    message = alertwords.said_changes("one", [change])
    assert message.title == "Port 443 on one does not answer from the internet over IPv4"


def test_a_second_message_about_a_port_comes_only_when_it_changes_again(con):
    host_id = add_host(con)
    both_families(con, host_id)
    probe(con, host_id, [("v4", 443, prober.STATE_NO_RESPONSE),
                         ("v6", 443, prober.STATE_CONNECTED)],
          started_at="2026-08-17T12:00:00+00:00")
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    assert len(finding_alerts.pending_deliveries(con, now=NOW + DEBOUNCE)) == 1
    # Passes with nothing new raise nothing more about this port.
    for minutes in (20, 25, 30):
        finding_alerts.evaluate(con, now=NOW + timedelta(minutes=minutes))
    raised = [r for r in changes(con) if r["outcome"] == finding_alerts.OUTCOME_RAISED]
    assert len(raised) == 1
    # The other family stopping is the port changing again, and is said.
    later = NOW + timedelta(minutes=40)
    probe(con, host_id, [("v4", 443, prober.STATE_NO_RESPONSE),
                         ("v6", 443, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T12:40:00+00:00")
    finding_alerts.evaluate(con, now=later)
    finding_alerts.evaluate(con, now=later + DEBOUNCE)
    raised = [r for r in changes(con) if r["outcome"] == finding_alerts.OUTCOME_RAISED]
    assert [r["family"] for r in raised] == ["v4", "v6"]
    assert raised[1]["other_family"] == alertwords.OTHER_DOES_NOT_ANSWER


def test_what_is_said_of_the_program_is_frozen_with_the_change(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[
        socket_row(443, process="caddy"), socket_row(8000, process="python3.12")]))
    for port in (443, 8000):
        intent.declare(con, "one", "tcp", port, "v4", "open")
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED),
                         ("v4", 8000, prober.STATE_CONNECTED)])
    finding_alerts.evaluate(con, now=NOW)
    probe(con, host_id, [("v4", 443, prober.STATE_NO_RESPONSE),
                         ("v4", 8000, prober.STATE_NO_RESPONSE)],
          started_at="2026-08-17T12:00:00+00:00")
    finding_alerts.evaluate(con, now=NOW)
    by_port = {r["port"]: r for r in changes(con)}
    assert (by_port[443]["program"], by_port[443]["program_said"]) == ("caddy", "caddy")
    # The page keeps the whole name. A message says nothing of it.
    assert (by_port[8000]["program"], by_port[8000]["program_said"]) == ("python3.12", "")


def test_the_mark_of_a_port_outside_its_rules_source_is_frozen_with_the_change(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    assert changes(con)[-1]["outside_source"] == 0
    # The engine's own field, written as it is on the finding.
    finding = next(f for host in join.fleet_findings(con) for f in host.findings)
    marked = dataclasses.replace(finding, answered_outside_the_rules_source=True)
    change_id = finding_alerts._open_change(
        con, host_id, marked, "", join.STATE_UNREVIEWED, NOW, findings=[marked])
    assert finding_alerts._change_row(con, change_id)["outside_source"] == 1
    # And it reaches the message from the row, not from a newer finding.
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    con.execute("UPDATE finding_changes SET outside_source = 1"
                " WHERE outcome = ?", (finding_alerts.OUTCOME_RAISED,))
    (_, items), = finding_alerts.pending_deliveries(con, now=NOW + DEBOUNCE)
    assert items[0][1].outside_source is True


def test_a_database_from_before_the_columns_reads_as_no_field(con):
    host_id = add_host(con)
    a_conflict_appears(con, host_id)
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    # A table from before the columns: they are added empty, and a row
    # written before them holds NULL in each.
    for column in ("allowed_by", "other_family", "outside_source",
                   "program_said", "was_program_said"):
        con.execute(f"ALTER TABLE finding_changes DROP COLUMN {column}")
    finding_alerts.init(con)
    (_, items), = finding_alerts.pending_deliveries(con, now=NOW + DEBOUNCE)
    change = items[0][1]
    assert (change.allowed_by, change.other_family, change.program_said,
            change.was_program_said) == ("", "", "", "")
    assert change.outside_source is False
    message = alertwords.said_changes("one", [change])
    assert message.fields == (("server", "one"), ("port", "443"),
                              ("you said", "reachable"))


def test_a_rule_edited_after_the_change_does_not_change_the_message(con):
    host_id = add_host(con)
    accept = ufw_v4(["tcp dport 443 accept"])
    report(con, host_id, document(sockets=[socket_row(443)], tables=[accept]))
    intent.declare(con, "one", "tcp", 443, "v4", "closed")
    probe(con, host_id, [("v4", 443, prober.STATE_NO_RESPONSE)])
    finding_alerts.evaluate(con, now=NOW)
    probe(con, host_id, [("v4", 443, prober.STATE_CONNECTED)],
          started_at="2026-08-17T12:00:00+00:00")
    finding_alerts.evaluate(con, now=NOW)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    row = [r for r in changes(con) if r["outcome"] == finding_alerts.OUTCOME_RAISED][-1]
    assert row["to_state"] == join.STATE_CONFLICT
    assert row["allowed_by"] == join.LAYER_HOST_FIREWALL
    # The rule is taken out of the server's firewall after the change.
    report(con, host_id, document(sockets=[socket_row(443)], tables=[ufw_v4([])],
                                  collected_at_unix=1_700_000_900),
           received_at="2026-08-17T12:20:00+00:00")
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE + timedelta(minutes=5))
    (_, items), = finding_alerts.pending_deliveries(con, now=NOW + DEBOUNCE)
    message = alertwords.said_changes("one", [change for _, change in items])
    assert dict(message.fields)["allowed by"] == "a rule in the server's firewall"
