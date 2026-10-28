"""The sweep looks for CVEs that are new and hands them out, once.

    python -m pytest tests/test_sweep_cves.py

The look and the sending have their own files, test_cvetell.py and
test_cvesend.py. This one holds that the timer calls them, that it does so
with the release's extract as it is kept beside the database, and that
nothing in the CVE check can stop the sweep, whose own work is the alerts.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app import cveextract, cvestore, cvetell, db, store, sweep_cli
from test_cvetell import FIRST, LATER, report, reports


@pytest.fixture()
def dbpath(tmp_path, monkeypatch):
    path = str(tmp_path / "cp.db")
    monkeypatch.setenv(db.DB_ENV, path)
    monkeypatch.delenv(cvestore.DIR_ENV, raising=False)
    # The sweep refuses a database that is not there, so it is made here.
    con = db.connect(path)
    db.init(con)
    con.close()
    return path


@pytest.fixture()
def sent(monkeypatch):
    """Every mail the run hands to a relay."""
    out = []

    def fake_send(subject, body, config=None, html=""):
        out.append((subject, body))
        return True, "sent"

    monkeypatch.setattr(sweep_cli.notify, "send", fake_send)
    return out


def keep(dbpath, rows, age=timedelta(hours=1)):
    """The release's extract, put where the control plane keeps it."""
    modified = (datetime.now(timezone.utc) - age).strftime("%Y-%m-%dT%H:%M:%SZ")
    where = cvestore.directory({db.DB_ENV: dbpath})
    data = cveextract.dump(rows, "debian", "12", source_modified=modified)
    where.mkdir(parents=True, exist_ok=True)
    (where / "debian-12.tsv.gz").write_bytes(data)


def sweep():
    assert sweep_cli.main([]) == 0


def server(dbpath, name="web-07"):
    sweep()     # makes every table
    con = db.connect(dbpath)
    host_id, _ = store.add_host(con, name)
    reports(con, host_id, report())
    con.close()


def cve_mails(sent):
    return [subject for subject, _body in sent if "CVE" in subject]


def test_a_sweep_tells_a_new_cve_once(dbpath, sent):
    keep(dbpath, FIRST)
    server(dbpath)
    sweep()
    assert cve_mails(sent) == [], "what was there at the first look was mailed"
    keep(dbpath, LATER)
    sweep()
    # The title and `CVEs` are the mark's on the server's page, which stands
    # for three and has one fix the lists do not offer. One of them is new.
    assert cve_mails(sent) == ["[whichports] A newer version fixes CVEs on web-07"]
    assert "  CVEs: 3\n  new: 1\n" in [body for subject, body in sent if "CVE" in subject][0]
    for _ in range(3):
        sweep()
    assert len(cve_mails(sent)) == 1


def test_a_sweep_says_what_it_told(dbpath, sent, capsys):
    keep(dbpath, FIRST)
    server(dbpath)
    sweep()
    keep(dbpath, LATER)
    capsys.readouterr()
    sweep()
    assert "CVEs: 1 workspace told, 1 sent" in capsys.readouterr().out
    sweep()
    assert "CVEs:" not in capsys.readouterr().out, "a sweep with nothing to tell says nothing of CVEs"


def test_a_dry_run_looks_at_no_cve_and_writes_nothing(dbpath, sent):
    keep(dbpath, FIRST)
    server(dbpath)
    assert sweep_cli.main(["--dry-run"]) == 0
    con = db.connect(dbpath)
    assert con.execute("SELECT COUNT(*) FROM cve_started").fetchone()[0] == 0
    assert con.execute("SELECT COUNT(*) FROM cve_told").fetchone()[0] == 0
    con.close()
    assert cve_mails(sent) == []


def test_an_extract_that_is_not_whole_tells_nobody_and_the_sweep_stands(dbpath, sent, capsys):
    keep(dbpath, FIRST)
    server(dbpath)
    sweep()
    where = cvestore.directory({db.DB_ENV: dbpath})
    (where / "debian-12.tsv.gz").write_bytes(b"not an extract")
    sweep()
    assert cve_mails(sent) == []
    assert "checked 1 hosts" in capsys.readouterr().out


def test_a_fault_in_the_cve_look_does_not_stop_the_sweep(dbpath, sent, capsys, monkeypatch):
    """The sweep's own work is the alerts. Whatever goes wrong in the check,
    the sweep says so with the fault's class and goes on to its end."""
    keep(dbpath, FIRST)
    server(dbpath)

    def broken(*_args, **_kwargs):
        raise RuntimeError("a secret that must not be printed")

    monkeypatch.setattr(cvetell, "evaluate", broken)
    capsys.readouterr()
    sweep()
    out = capsys.readouterr().out
    assert "the CVE look failed: RuntimeError" in out and "a secret" not in out
    assert "checked 1 hosts" in out


def test_a_fault_in_the_cve_sending_does_not_stop_the_sweep(dbpath, sent, capsys, monkeypatch):
    keep(dbpath, FIRST)
    server(dbpath)
    sweep()
    keep(dbpath, LATER)

    def broken(*_args, **_kwargs):
        raise RuntimeError("a secret that must not be printed")

    monkeypatch.setattr(sweep_cli.cvesend, "deliver", broken)
    capsys.readouterr()
    sweep()
    out = capsys.readouterr().out
    assert "the CVE sending failed: RuntimeError" in out and "a secret" not in out
    assert "checked 1 hosts" in out
