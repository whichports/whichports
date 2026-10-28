"""A report from an agent that sends the packages section, read by a control
plane that does not know it yet.

    python -m pytest tests/test_report_with_packages.py

The agent's report grows by additive sections only (`docs/PRODUCT.md` 4e,
principle 1), and the packages section (`docs/RECORD.md` 4.274) is the newest.
An agent with it can report to a control plane without it, because agents are
upgraded on their owners' schedule and the control plane on ours. So the
report must be taken exactly as one without the section is, and stored byte
for byte, so that the control plane that does read it later finds what was
sent. The section below is shaped as the agent writes it and its values are
made up.
"""
import json

import pytest
from fastapi.testclient import TestClient

from app import db, ingest, store
from operator_gate import gate

PACKAGES = {
    "status": "collected",
    "sources": {"os_release": {"status": "collected"}, "dpkg_status": {"status": "collected"},
                "dpkg_info": {"status": "collected"}, "dpkg_diversions": {"status": "collected"}},
    "distribution": {"id": "debian", "version_id": "12", "version_codename": "bookworm"},
    "units": [
        {"unit": "ssh.service", "finding": "complete",
         "unit_file": {"path": "/usr/lib/systemd/system/ssh.service",
                       "owners": [{"name": "openssh-server", "architecture": "arm64",
                                   "installed": True, "version": "1:9.0p1-1", "source": "openssh"}]},
         "program": {"path": "/usr/sbin/sshd",
                     "owners": [{"name": "openssh-server", "architecture": "arm64",
                                 "installed": True, "version": "1:9.0p1-1", "source": "openssh"}]},
         "program_kind": "elf"},
        {"unit": "postgresql@15-main.service", "finding": "exec_start_prefixed",
         "unit_file": {"path": "/usr/lib/systemd/system/postgresql@.service",
                       "owners": [{"name": "postgresql-common", "architecture": "all",
                                   "installed": True, "version": "248"}]}},
        # a finding a later agent may add, which nothing here may choke on
        {"unit": "app.service", "finding": "a_finding_from_the_future"},
    ],
}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def credential(client, name):
    answer = client.post("/api/admin/hosts", content=json.dumps({"name": name}), headers=gate())
    assert answer.status_code == 201
    return answer.json()["credential"]


def document(with_packages):
    doc = {"schema_version": 1, "collected_at_unix": 1, "hostname": "web-01",
           "agent_version": "0.1.13",
           "sockets": {"status": "collected", "listening": [
               {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 22,
                "cgroup": "/system.slice/ssh.service", "unit": "ssh.service"}]}}
    if with_packages:
        doc["packages"] = PACKAGES
    return doc


def post(client, cred, body):
    return client.post("/api/v1/reports", content=body,
                       headers={"Authorization": f"Bearer {cred}"})


def stored_document(name):
    con = db.connect()
    try:
        host = store.active_host_by_name(con, name)
        return store.latest_report(con, host["id"])["document"]
    finally:
        con.close()


def test_a_report_with_the_section_is_taken_like_one_without(client):
    plain = post(client, credential(client, "plain"), json.dumps(document(False)))
    newer = post(client, credential(client, "newer"), json.dumps(document(True)))
    assert newer.status_code == plain.status_code < 300
    # the answer is an acknowledgement the agent acts on nothing in (SI-2),
    # and it is the same answer either way
    assert newer.content == plain.content


def test_the_section_is_stored_byte_for_byte(client):
    body = json.dumps(document(True), indent=2)
    assert post(client, credential(client, "web-01"), body).status_code < 300
    assert json.loads(stored_document("web-01")) == json.loads(body)
    assert json.loads(stored_document("web-01"))["packages"] == PACKAGES


def test_the_largest_section_the_agent_can_send_is_taken(client):
    """The agent caps the section so that, with every cap at once, it
    marshals to about 1.9 MB (agent/internal/hostdoc/packages_test.go). A
    report that size is under the ingest's limit and is taken."""
    field = "9" * 128
    owner = {"name": field, "architecture": field, "installed": True, "version": field,
             "source": field, "source_version": field}
    path = {"path": "/" + "a" * 511, "owners": [owner, owner], "diverted": True}
    doc = document(True)
    doc["packages"] = dict(PACKAGES, units_cut=True, units=[
        {"unit": f"{'u' * 243}{i:04d}.service", "finding": "over_cap", "unit_file": path,
         "program": path, "program_kind": "not_read", "program_target": path}
        for i in range(256)])
    body = json.dumps(doc, indent=2)
    assert 1_500_000 < len(body) < ingest.MAX_DOCUMENT_BYTES
    assert post(client, credential(client, "big"), body).status_code < 300
