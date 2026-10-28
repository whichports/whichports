"""The five-minute sweep renews published proofs and writes down the lapsed
ones (RECORD 4.104, part 3). What is reviewed here is the wiring and the
printed lines; the renewal rules themselves are test_authz_renewal.py's."""
from datetime import timedelta

import pytest

from app import alerts, authz, db, finding_alerts, intent, prober, store, sweep_cli

ADDRESS = "185.199.108.153"


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
    authz.init(con)
    con.close()
    return path


@pytest.fixture()
def quiet_mail(monkeypatch):
    monkeypatch.setattr(sweep_cli.notify, "send", lambda *a, **k: (True, "sent"))


def proof_about_to_lapse(path, days_left=3.0):
    """A verified http proof last read more than a day ago, so due for its
    daily reading on the real clock the sweep runs on, with this much life
    left."""
    con = db.connect(path)
    now = authz._now()
    challenge = authz.start_proof(con, ADDRESS, authz.METHOD_HTTP_TOKEN, now=now)
    result = authz.verify_proof(con, challenge.id, now=now,
                                fetcher=lambda url, timeout=0: challenge.token)
    assert result.recorded
    con.execute("UPDATE authorizations SET expires_at = ?, verified_at = ?"
                " WHERE target = ?",
                ((now + timedelta(days=days_left)).isoformat(),
                 (now - timedelta(days=1, minutes=1)).isoformat(), ADDRESS))
    con.commit()
    con.close()
    return challenge.token


def expiry(path):
    con = db.connect(path)
    row = con.execute("SELECT expires_at, renewal_failure FROM authorizations"
                      " WHERE target = ?", (ADDRESS,)).fetchone()
    con.close()
    return row


def test_the_sweep_renews_a_proof_still_published(dbpath, quiet_mail, monkeypatch, capsys):
    token = proof_about_to_lapse(dbpath)
    before = expiry(dbpath)["expires_at"]
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: token)
    assert sweep_cli.main([]) == 0
    out = capsys.readouterr().out
    assert f"renewed: the proof for {ADDRESS} was read again" in out
    assert expiry(dbpath)["expires_at"] > before


def test_the_sweep_says_when_the_evidence_is_gone(dbpath, quiet_mail, monkeypatch, capsys):
    proof_about_to_lapse(dbpath)
    def gone(url, timeout=0):
        raise authz.ProofError(f"could not read {url}: HTTP 404")
    monkeypatch.setattr(authz, "fetch_token_file", gone)
    assert sweep_cli.main([]) == 0
    out = capsys.readouterr().out
    assert f"not renewed: {ADDRESS}: could not read" in out
    assert "could not read" in expiry(dbpath)["renewal_failure"]


def test_the_sweep_says_when_a_proof_ends(dbpath, quiet_mail, monkeypatch, capsys):
    proof_about_to_lapse(dbpath)
    monkeypatch.setattr(authz, "fetch_token_file",
                        lambda url, timeout=0: "somebody else's page")
    assert sweep_cli.main([]) == 0
    out = capsys.readouterr().out
    assert f"ended: the proof for {ADDRESS} is gone from where it was published" in out


def test_the_sweep_writes_a_lapse_down(dbpath, quiet_mail, monkeypatch, capsys):
    proof_about_to_lapse(dbpath, days_left=-0.5)
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: "never asked")
    assert sweep_cli.main([]) == 0
    out = capsys.readouterr().out
    assert f"lapsed: the proof for {ADDRESS} has expired" in out
    assert "renewed:" not in out


def test_a_dry_run_still_renews_because_reading_evidence_sends_nothing(dbpath, monkeypatch, capsys):
    """Dry run means no alert leaves. Renewal reads a file the operator
    published and mails nobody, so it is not the thing dry run withholds."""
    token = proof_about_to_lapse(dbpath)
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: token)
    assert sweep_cli.main(["--dry-run"]) == 0
    assert "renewed:" in capsys.readouterr().out


def test_nothing_is_printed_when_no_proof_is_due(dbpath, quiet_mail, monkeypatch, capsys):
    store.add_host(con := db.connect(dbpath), "box"); con.close()
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: "never asked")
    assert sweep_cli.main([]) == 0
    out = capsys.readouterr().out
    assert "renewed:" not in out and "not renewed:" not in out and "lapsed:" not in out
