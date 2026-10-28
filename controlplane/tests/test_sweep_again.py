"""The sweep tells a channel that a silent agent reports again.

    python -m pytest tests/test_sweep_again.py

`tests/test_reportingagain.py` holds the rule. This is the timer's own run,
`sweep_cli.main`, with the relay and the webhook stood in for: the message
about the silence goes out, the agent reports, and the next run says so
once. The server is made up.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app import alerts, db, finding_alerts, intent, prober, reportingagain, store, sweep_cli


@pytest.fixture()
def dbpath(tmp_path, monkeypatch):
    path = str(tmp_path / "cp.db")
    monkeypatch.setenv(db.DB_ENV, path)
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", "operator@example.com")
    monkeypatch.setenv("WHICHPORTS_WEBHOOK_URL", "https://hooks.example.com/x")
    con = db.connect(path)
    for module in (db, prober, intent, alerts, finding_alerts):
        module.init(con)
    con.close()
    return path


@pytest.fixture()
def out(monkeypatch):
    """Every mail and every post the run hands over, and a switch that makes
    the webhook fail."""
    class Out:
        mails, posts, webhook_ok = [], [], True
    seen = Out()
    seen.mails, seen.posts = [], []

    def mail(subject, body, config=None, html=""):
        seen.mails.append((subject, body))
        return True, "sent"

    def post(payload, config=None, resolver=None, opener=None):
        if not seen.webhook_ok:
            return False, "the endpoint could not be reached: OSError"
        seen.posts.append(payload)
        return True, "posted"

    monkeypatch.setattr(sweep_cli.notify, "send", mail)
    monkeypatch.setattr(sweep_cli.webhook, "send", post)
    return seen


def report(path, name, ago):
    """A report that arrived `ago` before now, as `store.insert_report`
    writes one. The report an agent is back with arrives now, which is
    after its silence was raised."""
    when = (datetime.now(timezone.utc) - ago).isoformat()
    con = db.connect(path)
    row = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()
    host_id = row[0] if row else store.add_host(con, name)[0]
    con.execute("INSERT INTO reports (host_id, received_at, collected_at_unix, schema_version, document)"
                " VALUES (?, ?, 1, 1, '{}')", (host_id, when))
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?", (when, host_id))
    con.commit()
    con.close()


def subjects(out):
    return [subject for subject, _body in out.mails]


def test_a_silence_is_told_and_then_that_the_agent_reports_again_once(dbpath, out, capsys):
    report(dbpath, "web-07", timedelta(minutes=50))
    sweep_cli.main([])
    assert subjects(out) == ["[whichports] web-07 stopped reporting"]
    assert [post["kind"] for post in out.posts] == ["silent"]
    report(dbpath, "web-07", timedelta(0))
    sweep_cli.main([])
    assert subjects(out)[1:] == ["[whichports] web-07 is reporting again"]
    # From the report of fifty minutes ago to the one that just arrived.
    assert "  server: web-07\n  no report for: 50 minutes\n" in out.mails[1][1]
    assert "reporting again: 2 sent" in capsys.readouterr().out
    again = out.posts[1]
    assert (again["kind"], again["server"]) == (reportingagain.KIND_AGAIN, "web-07")
    assert again["raised_at"] == out.posts[0]["raised_at"], "a program cannot pair the two"
    assert again["text"].startswith("whichports: web-07 is reporting again")
    for _ in range(3):
        sweep_cli.main([])
    assert len(out.mails) == 2 and len(out.posts) == 2


def test_a_webhook_that_failed_then_is_told_at_the_next_run_and_the_mail_not_twice(dbpath, out):
    report(dbpath, "web-07", timedelta(minutes=50))
    sweep_cli.main([])
    report(dbpath, "web-07", timedelta(0))
    out.webhook_ok = False
    sweep_cli.main([])
    assert subjects(out)[1:] == ["[whichports] web-07 is reporting again"] and len(out.posts) == 1
    out.webhook_ok = True
    sweep_cli.main([])
    assert len(out.mails) == 2
    assert [post["kind"] for post in out.posts] == ["silent", reportingagain.KIND_AGAIN]


def test_a_channel_that_never_heard_of_the_silence_hears_nothing(dbpath, out):
    """The webhook failed when the silence was told, and the agent was back
    before it was tried again. A resolved alert is not sent late, so the
    webhook was never told it stopped and is not told it is back."""
    report(dbpath, "web-07", timedelta(minutes=50))
    out.webhook_ok = False
    sweep_cli.main([])
    assert subjects(out) == ["[whichports] web-07 stopped reporting"] and out.posts == []
    out.webhook_ok = True
    report(dbpath, "web-07", timedelta(0))
    sweep_cli.main([])
    assert subjects(out)[1:] == ["[whichports] web-07 is reporting again"]
    assert out.posts == []


def test_a_fault_in_it_never_fails_the_sweep(dbpath, out, monkeypatch, capsys):
    def broken(*args, **kwargs):
        raise RuntimeError("a fault with text that must not be printed")
    monkeypatch.setattr(sweep_cli.reportingagain, "deliver", broken)
    report(dbpath, "web-07", timedelta(minutes=50))
    assert sweep_cli.main([]) == 0
    printed = capsys.readouterr().out
    assert "the reporting again message failed: RuntimeError" in printed
    assert "must not be printed" not in printed
    assert subjects(out) == ["[whichports] web-07 stopped reporting"]


def test_a_dry_run_sends_none_of_it_and_settles_nothing(dbpath, out):
    report(dbpath, "web-07", timedelta(minutes=50))
    sweep_cli.main([])
    report(dbpath, "web-07", timedelta(0))
    sweep_cli.main(["--dry-run"])
    assert len(out.mails) == 1 and len(out.posts) == 1
    con = db.connect(dbpath)
    assert con.execute("SELECT COUNT(*) FROM silence_told WHERE again_at IS NULL").fetchone()[0] == 2
    con.close()
    sweep_cli.main([])
    assert len(out.mails) == 2 and len(out.posts) == 2
