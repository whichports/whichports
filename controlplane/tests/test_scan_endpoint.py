"""The Scan-now endpoint: its gate, its 404s, and the promise that touching the
trigger file can never fail an accepted request.

The fixture and the gate pattern are test_admin.py's, read there first.
"""

import json

import pytest
from fastapi.testclient import TestClient

from app import db, ingest, scan, store
from operator_gate import gate

ONESHOT = "sudo whichports-agent --mode=oneshot"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def create(client, name):
    return client.post("/api/admin/hosts", content=json.dumps({"name": name}),
                       headers=gate())


# ----------------------------------------------------------------- the gate

def test_scan_without_the_gate_header_is_403(client):
    assert client.post("/api/admin/hosts/x/scan").status_code == 403


def test_scan_of_an_unknown_host_is_404(client):
    assert client.post("/api/admin/hosts/ghost/scan", headers=gate()).status_code == 404


def test_scan_of_a_revoked_host_is_404(client):
    """Revoked and unknown 404 identically, the same as the other admin
    routes."""
    create(client, "box")
    client.post("/api/admin/hosts/box/revoke", headers=gate())
    assert client.post("/api/admin/hosts/box/scan", headers=gate()).status_code == 404


# ----------------------------------------------------------- the response

def test_a_fresh_scan_is_accepted_and_carries_the_oneshot_command(client):
    create(client, "box")
    resp = client.post("/api/admin/hosts/box/scan", headers=gate())
    assert resp.status_code == 200
    body = resp.json()
    assert body["accepted"] is True
    assert body["retry_after"] == 0
    assert body["sentence"]
    assert body["oneshot_command"] == ONESHOT


def test_the_response_has_exactly_the_four_keys(client):
    create(client, "box")
    body = client.post("/api/admin/hosts/box/scan", headers=gate()).json()
    assert set(body) == {"accepted", "sentence", "retry_after", "oneshot_command"}


def test_a_second_scan_is_refused_with_a_sentence_and_a_wait(client):
    create(client, "box")
    client.post("/api/admin/hosts/box/scan", headers=gate())
    body = client.post("/api/admin/hosts/box/scan", headers=gate()).json()
    assert body["accepted"] is False
    assert isinstance(body["retry_after"], int)
    assert body["retry_after"] > 0
    assert "Try again" in body["sentence"]
    # The command to refresh the inside view is offered even on a refusal,
    # because an operator may still want it while the re-probe is on cooldown.
    assert body["oneshot_command"] == ONESHOT


def test_the_response_carries_no_credential(client):
    """SI-5 and the one-time-credential design: nothing here is a secret, and
    the host is already enrolled, so no credential appears."""
    credential = create(client, "box").json()["credential"]
    scan_body = client.post("/api/admin/hosts/box/scan", headers=gate()).json()
    assert credential not in json.dumps(scan_body)
    assert "credential" not in scan_body


# ------------------------------------------------- the trigger is best effort

def test_an_accepted_scan_touches_the_trigger_file(client, tmp_path):
    """The fast path: an accepted request writes the trigger so the path unit
    fires at once."""
    create(client, "box")
    trigger = tmp_path / scan.TRIGGER_FILENAME
    assert not trigger.exists()
    client.post("/api/admin/hosts/box/scan", headers=gate())
    assert trigger.exists()


def test_a_failing_trigger_write_does_not_fail_the_request(client, monkeypatch):
    """The request is already recorded when the trigger is touched, and the next
    fast-lane pass covers it, so a trigger that cannot be written is logged and
    swallowed rather than turned into an error the operator sees."""
    create(client, "box")

    def boom(_path):
        raise OSError("read-only file system")

    monkeypatch.setattr(scan, "touch_trigger", boom)
    resp = client.post("/api/admin/hosts/box/scan", headers=gate())
    assert resp.status_code == 200
    assert resp.json()["accepted"] is True
    # And the request really is recorded, so the drain will still find it.
    con = db.connect()
    host_id = store.active_host_by_name(con, "box")["id"]
    pending = scan.pending_requests(con)
    con.close()
    assert pending == [host_id]


def test_a_refused_scan_does_not_touch_the_trigger(client, tmp_path):
    """Only an accepted request fires the responder. A refusal recorded nothing
    new, so there is nothing to drain."""
    create(client, "box")
    client.post("/api/admin/hosts/box/scan", headers=gate())
    trigger = tmp_path / scan.TRIGGER_FILENAME
    trigger.unlink()
    client.post("/api/admin/hosts/box/scan", headers=gate())  # refused, too soon
    assert not trigger.exists()
