"""A server deleted during the finding pass is left out, and the pass goes on.

    python -m pytest tests/test_finding_pass_server_deleted.py

The same fault the probe pass had (docs/RECORD.md 4.312, 4.315), read in this
pass's code before anybody met it. The sweep runs the finding pass every five
minutes. The pass works out the whole fleet's findings first, one server
after another, and then writes each server's rows. A server deleted in the
dashboard between the two has no row to hang its findings on, the database
refuses the first of them, and the run ended there: nothing more written for
anybody, and nothing mailed or posted in that run.

A server that is gone when its rows are written is not an error. The pass
leaves it out, the sweep says so in a line of its own, and the rest of the
fleet's changes are written and sent in the same run. Any other refusal from
the database still ends the run.
"""
import re
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app import alerts, finding_alerts, intent, join, prober, store, sweep_cli
from test_sweep_cli import (DEBOUNCE, NOW, con_for, dbpath, document,  # noqa: F401
                            probe, sent)

NAMES = ("first", "middle", "last")


def a_change_is_due_on(path, name, port=443):
    """One server whose port was declared open, answered, and now does not:
    a change that has confirmed and is due to be told. The steps of
    test_sweep_cli.a_change_is_due, for a server of any name."""
    con = con_for(path)
    host_id, _ = store.add_host(con, name)
    doc = document((port,))
    doc["hostname"] = name
    store.insert_report(con, host_id, 1, 1, json.dumps(doc))
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), host_id))
    con.commit()
    intent.declare(con, name, "tcp", port, "v4", "open")
    wall = datetime.now(timezone.utc)
    probe(con, host_id, [(port, prober.STATE_CONNECTED)],
          (wall - timedelta(minutes=40)).isoformat())
    finding_alerts.evaluate(con, now=NOW)
    probe(con, host_id, [(port, prober.STATE_NO_RESPONSE)],
          (wall - timedelta(minutes=10)).isoformat())
    finding_alerts.evaluate(con, now=NOW)
    con.close()
    return host_id


def three_changes_waiting(path):
    """Three servers, each with a change seen and not yet confirmed. The next
    pass after the debounce confirms all three and raises an alert for each."""
    for name in NAMES:
        a_change_is_due_on(path, name)


def delete_server(con, name):
    assert store.revoke_host(con, name)
    assert store.delete_host(con, name)


def deleted_after_the_walk(monkeypatch, name):
    """The fleet's findings are worked out, and then somebody deletes one
    server, before its rows are written."""
    real = join.fleet_findings
    walks = []

    def walk_then_delete(con, **kwargs):
        found = real(con, **kwargs)
        # Once, after the first walk of a run, which is the finding pass's.
        # The sweep walks the fleet a second time for the outside view's age.
        if not walks:
            delete_server(con, name)
        walks.append(len(found))
        return found

    monkeypatch.setattr(finding_alerts.join, "fleet_findings", walk_then_delete)
    return walks


def alerts_by_host(path):
    con = con_for(path)
    rows = con.execute(
        "SELECT h.name AS name, a.notified_at AS notified_at FROM alerts a"
        " JOIN hosts h ON h.id = a.host_id WHERE a.kind = ? ORDER BY h.name",
        (finding_alerts.KIND_FINDING,)).fetchall()
    con.close()
    return [(row["name"], row["notified_at"] is not None) for row in rows]


def told_about(sent):
    """The servers the mails of a run were about, from each subject, which
    reads "[whichports] Port 443 on <server> ..."."""
    return sorted(re.search(r" on (\S+)", subject).group(1) for subject, _ in sent)


def mail_by_environment(monkeypatch):
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", "ops@example.org")
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")


# -------------------------------------------------------------------- the pass

def test_the_pass_writes_the_rest_of_the_fleet(dbpath, monkeypatch):
    three_changes_waiting(dbpath)
    deleted_after_the_walk(monkeypatch, "middle")
    con = con_for(dbpath)
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    con.close()
    assert result["gone"] == ["middle"]
    raised = sorted(label.split(" ", 1)[0] for label in result["raised"])
    assert raised == ["first", "last"], result["raised"]
    assert [name for name, _ in alerts_by_host(dbpath)] == ["first", "last"]


def test_a_server_deleted_before_the_walk_was_never_in_it(dbpath, monkeypatch):
    """Not this fault, and held so the two stay apart: the walk itself leaves
    out a server that is gone when its turn comes."""
    three_changes_waiting(dbpath)
    con = con_for(dbpath)
    delete_server(con, "middle")
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    con.close()
    assert result["gone"] == []
    assert [name for name, _ in alerts_by_host(dbpath)] == ["first", "last"]


def test_a_server_that_was_only_removed_is_no_error_and_is_not_left_out(dbpath, monkeypatch):
    three_changes_waiting(dbpath)
    con = con_for(dbpath)
    assert store.revoke_host(con, "middle")
    result = finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    con.close()
    assert result["gone"] == []


def test_any_other_refusal_still_ends_the_pass(dbpath, monkeypatch):
    """Only a server that is gone is left out. A refused write for a server
    that is still there is an error nobody has explained."""
    three_changes_waiting(dbpath)

    def broken(*args, **kwargs):
        raise sqlite3.IntegrityError("NOT NULL constraint failed: alerts.detail")

    monkeypatch.setattr(finding_alerts.alerts, "raise_alert", broken)
    con = con_for(dbpath)
    with pytest.raises(sqlite3.IntegrityError):
        finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    con.close()


# ------------------------------------------------------------------- the sweep

def confirm_on_the_next_sweep(path):
    """The sweep reads the wall clock, so the three changes are made due the
    way test_sweep_cli does it: seen long enough ago for the debounce."""
    con = con_for(path)
    finding_alerts.evaluate(con, now=NOW + DEBOUNCE)
    con.close()


def test_the_sweep_says_so_and_sends_the_others_in_the_same_run(
        dbpath, sent, monkeypatch, capsys):
    mail_by_environment(monkeypatch)
    three_changes_waiting(dbpath)
    confirm_on_the_next_sweep(dbpath)        # three alerts raised, none sent yet
    assert alerts_by_host(dbpath) == [("first", False), ("last", False), ("middle", False)]
    walks = deleted_after_the_walk(monkeypatch, "middle")

    assert sweep_cli.main([]) == 0
    said = capsys.readouterr().out
    assert "left out: middle was deleted during the pass" in said
    # the walk that held the deleted server was the finding pass's own
    assert walks[0] == 3 and walks[1:] == [2], walks
    # the other two went out in this run, one mail each
    assert told_about(sent) == ["first", "last"], sent
    assert alerts_by_host(dbpath) == [("first", True), ("last", True)]


def test_the_next_run_sends_nothing_twice(dbpath, sent, monkeypatch):
    """A run that left one server out must not leave the others to be told
    again."""
    mail_by_environment(monkeypatch)
    three_changes_waiting(dbpath)
    confirm_on_the_next_sweep(dbpath)
    deleted_after_the_walk(monkeypatch, "middle")
    sweep_cli.main([])
    assert told_about(sent) == ["first", "last"]
    # the next run, five minutes on: the server stays gone, nothing new
    assert sweep_cli.main([]) == 0
    assert told_about(sent) == ["first", "last"], sent[2:]


def test_nothing_is_marked_delivered_for_the_server_that_went(dbpath, sent, monkeypatch):
    """Its alerts went with it. No delivery row and no line in any table
    names it afterwards."""
    mail_by_environment(monkeypatch)
    three_changes_waiting(dbpath)
    confirm_on_the_next_sweep(dbpath)
    deleted_after_the_walk(monkeypatch, "middle")
    sweep_cli.main([])
    con = con_for(dbpath)
    hosts = [row["name"] for row in con.execute("SELECT name FROM hosts ORDER BY name")]
    orphans = con.execute(
        "SELECT COUNT(*) FROM alerts WHERE host_id NOT IN (SELECT id FROM hosts)").fetchone()[0]
    deliveries = con.execute(
        "SELECT COUNT(*) FROM alert_deliveries WHERE alert_id NOT IN (SELECT id FROM alerts)"
    ).fetchone()[0]
    con.close()
    assert hosts == ["first", "last"]
    assert (orphans, deliveries) == (0, 0)
    assert "middle" not in told_about(sent)
