"""Which CVEs a workspace was told, so each is told once.

    python -m pytest tests/test_cvetell.py

`docs/SPEC-cve-check.md`, section 2, point 7, and section 4, point 11. The
message ends "Nothing else will be sent about these CVEs", and this is what
keeps that. The servers and the CVE numbers are made up.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import (alerts, cveextract, cvematch, cvestore, cvetell, db, finding_alerts,
                 intent, store)
from app.cveextract import Row

NOW = datetime(2026, 10, 4, 9, 0, tzinfo=timezone.utc)
FIRST = [Row("openssh", "CVE-2026-00001", "1:9.2p1-2+deb12u5", "low"),
         Row("nginx", "CVE-2026-00002", "1.22.1-9+deb12u10", "low")]
LATER = FIRST + [Row("openssh", "CVE-2026-00003", "1:9.2p1-2+deb12u10", "low")]


def extracts(rows, modified="2026-10-03T14:07:28Z"):
    kept = cvestore.Stored(cveextract.Header("debian", "12", True, modified), cvematch.by_source(rows))
    return lambda distribution, version_id: kept if (distribution, version_id) == ("debian", "12") else None


def owner(name, version, source=""):
    out = {"name": name, "architecture": "arm64", "installed": True, "version": version}
    if source:
        out["source"] = source
    return out


def unit(name, program, package):
    return {"unit": name, "finding": "complete", "program_kind": "elf",
            "unit_file": {"path": "/usr/lib/systemd/system/" + name, "owners": [package]},
            "program": {"path": program, "owners": [package]}}


def offer(version):
    return {"version": version, "archive": "debian", "not_automatic": False, "but_automatic_upgrades": False}


def report(ssh="1:9.2p1-2+deb12u3", ssh_offered="1:9.2p1-2+deb12u10", packages=True):
    """A server with OpenSSH on 22, whose lists offer the fix, and nginx on
    80, whose lists offer nothing newer than what is installed."""
    doc = {"schema_version": 1, "hostname": "h", "collected_at_unix": 1,
           "sockets": {"status": "collected", "listening": [
               {"protocol": "tcp", "family": "v4", "port": 22, "cgroup": "/system.slice/ssh.service", "unit": "ssh.service"},
               {"protocol": "tcp", "family": "v4", "port": 80, "cgroup": "/system.slice/nginx.service", "unit": "nginx.service"}]}}
    if packages:
        doc["packages"] = {
            "status": "collected",
            "sources": {"dpkg_info": {"status": "collected"}, "apt_lists": {"status": "collected"}},
            "distribution": {"id": "debian", "version_id": "12", "version_codename": "bookworm"},
            "units": [unit("ssh.service", "/usr/sbin/sshd", owner("openssh-server", ssh, "openssh")),
                      unit("nginx.service", "/usr/sbin/nginx", owner("nginx", "1.22.1-9"))],
            "offers": [{"name": "openssh-server", "offered": [offer(ssh_offered)],
                        "other_offers": False, "other_offers_installed": False},
                       {"name": "nginx", "offered": [offer("1.22.1-9")],
                        "other_offers": False, "other_offers_installed": False}]}
    return doc


@pytest.fixture
def con(tmp_path):
    con = db.connect(str(tmp_path / "cp.db"))
    for module in (db, intent, alerts, finding_alerts, cvetell):
        module.init(con)
    return con


def server(con, name, doc=None, workspace_id=db.DEFAULT_WORKSPACE_ID):
    host_id, _credential = store.add_host(con, name, workspace_id=workspace_id)
    reports(con, host_id, doc or report())
    return host_id


def reports(con, host_id, doc):
    store.insert_report(con, host_id, doc["collected_at_unix"], doc["schema_version"], json.dumps(doc))
    con.commit()


def look(con, rows=FIRST, now=NOW):
    """One evaluation, and the batches it wrote as plain data."""
    ids = cvetell.evaluate(con, now=now, extract_for=extracts(rows))
    return [cvetell.batch(con, batch_id) for batch_id in ids]


def told(con, host_id):
    return sorted(cvetell.told(con, host_id))


# ------------------------------------------------------------ told once

def test_the_first_look_at_a_port_is_a_starting_point_and_tells_nobody(con):
    """The day the check ships, and the day an agent first sends its
    packages, nobody is mailed about what was already there. It is on the
    screen."""
    web = server(con, "web-07")
    assert look(con) == []
    assert told(con, web) == [("tcp", 22, "CVE-2026-00001"), ("tcp", 80, "CVE-2026-00002")]
    assert look(con) == []


def test_a_cve_that_is_new_on_a_port_is_told_and_only_it(con):
    web = server(con, "web-07")
    look(con)
    batches = look(con, LATER)
    assert batches == [cvetell.Batch(workspace_id=db.DEFAULT_WORKSPACE_ID, told=(
        cvetell.ToldServer(host_id=web, host_name="web-07", ports=(("tcp", 22),),
                           cves=("CVE-2026-00003",), offered=True,
                           # What the server's mark stood for then: the new
                           # one, and the two its ports already carried. One
                           # of those is fixed in a version the lists do not
                           # offer, so the mark does not say an update.
                           marked=("CVE-2026-00001", "CVE-2026-00002", "CVE-2026-00003"),
                           mark_offered=False,
                           by_port=((("tcp", 22), ("CVE-2026-00003",)),),
                           # And port by port, so a port silenced before a
                           # try leaves the count (finding G9).
                           mark_by_port=((("tcp", 22), ("CVE-2026-00001", "CVE-2026-00003"), True),
                                         (("tcp", 80), ("CVE-2026-00002",), False))),))]
    assert ("tcp", 22, "CVE-2026-00003") in told(con, web)


def test_a_workspace_is_told_once_about_a_cve_on_a_port(con):
    server(con, "web-07")
    look(con)
    assert len(look(con, LATER)) == 1
    for _ in range(3):
        assert look(con, LATER, now=NOW + timedelta(hours=1)) == []


def test_a_set_that_shrinks_tells_nobody(con):
    """An update was installed, or the distribution took a CVE back."""
    web = server(con, "web-07")
    look(con, LATER)
    reports(con, web, report(ssh="1:9.2p1-2+deb12u10"))
    assert look(con, LATER) == []
    assert look(con, FIRST) == []


def test_a_cve_that_comes_back_on_a_port_is_not_told_twice(con):
    """A package put back to the older version after its update."""
    web = server(con, "web-07")
    look(con)
    assert len(look(con, LATER)) == 1
    reports(con, web, report(ssh="1:9.2p1-2+deb12u10"))
    assert look(con, LATER) == []
    reports(con, web, report(ssh="1:9.2p1-2+deb12u3"))
    assert look(con, LATER) == []


def test_a_package_put_back_to_an_older_version_is_told_what_is_new_to_the_port(con):
    """It does not matter which side moved: the distribution published a
    fix, or the server went back to a version the fix is not in."""
    web = server(con, "web-07", report(ssh="1:9.2p1-2+deb12u10"))
    assert look(con, LATER) == [] and told(con, web) == [("tcp", 80, "CVE-2026-00002")]
    reports(con, web, report(ssh="1:9.2p1-2+deb12u3"))
    [batch] = look(con, LATER)
    assert batch.told[0].cves == ("CVE-2026-00001", "CVE-2026-00003")


def test_a_fix_the_lists_do_not_offer_makes_the_batch_say_so(con):
    """The message says "an update" only when every fix told is offered."""
    web = server(con, "web-07")
    look(con)
    reports(con, web, report(ssh_offered="1:9.2p1-2+deb12u5"))
    [batch] = look(con, LATER)
    assert batch.told[0].cves == ("CVE-2026-00003",) and batch.told[0].offered is False


# ------------------------------------------------- what is never a message

def test_a_port_that_was_not_checked_starts_when_it_first_is_and_tells_nobody_then(con):
    """No data for the release yet, or lists that were not read. The day the
    port is first checked is its starting point, not a message about
    everything that was there all along."""
    web = server(con, "web-07")
    assert cvetell.evaluate(con, now=NOW, extract_for=lambda *_: None) == []
    assert told(con, web) == []
    assert look(con, LATER) == []
    assert len(told(con, web)) == 3
    assert look(con, LATER) == []


def test_data_older_than_three_days_tells_nobody_and_starts_nothing(con):
    web = server(con, "web-07")
    ids = cvetell.evaluate(con, now=NOW, extract_for=extracts(LATER, modified="2026-09-28T10:00:00Z"))
    assert ids == [] and told(con, web) == []


def test_a_report_with_no_packages_section_starts_nothing(con):
    """Every report of the published agent."""
    web = server(con, "web-07", report(packages=False))
    assert look(con, LATER) == [] and told(con, web) == []


def test_a_muted_server_and_a_silenced_port_are_out_of_the_message_and_its_counts(con):
    web = server(con, "web-07")
    quiet = server(con, "db-02")
    look(con)
    finding_alerts.mute_host(con, "db-02", now=NOW)
    finding_alerts.silence_port(con, "web-07", "tcp", 22, "v4", now=NOW)
    reports(con, web, report(ssh_offered="1:9.2p1-2+deb12u5"))
    later = LATER + [Row("nginx", "CVE-2026-00004", "1.22.1-9+deb12u11", "low")]
    [batch] = look(con, later)
    assert [(one.host_name, one.ports, one.cves) for one in batch.told] == [
        ("web-07", (("tcp", 80),), ("CVE-2026-00004",))]
    # Its counts too: what the mark stands for is port 80's two, and the
    # silenced port's are out of it as they are out of the server's mark on
    # the page (the second big test, finding G9, where a silenced port's two
    # made "CVEs: 14" of nginx's 12).
    [one] = batch.told
    assert one.marked == ("CVE-2026-00002", "CVE-2026-00004")
    assert [(port, ids) for port, ids, _update in one.mark_by_port] == [
        (("tcp", 80), ("CVE-2026-00002", "CVE-2026-00004"))]
    # A mute records and does not queue (docs/PRODUCT.md 4c): what became
    # new on the muted server and on the silenced port is written down as
    # known, in no batch, and is not said when the mute ends.
    assert ("tcp", 22, "CVE-2026-00003") in told(con, web)
    assert ("tcp", 22, "CVE-2026-00003") in told(con, quiet)
    in_a_batch = {(row[0], row[1]) for row in con.execute(
        "SELECT host_id, cve FROM cve_told WHERE batch_id IS NOT NULL")}
    assert in_a_batch == {(web, "CVE-2026-00004")}
    finding_alerts.unmute_host(con, "db-02", now=NOW)
    finding_alerts.unsilence_port(con, "web-07", "tcp", 22, "v4", now=NOW)
    assert look(con, later, now=NOW + timedelta(minutes=5)) == []


def test_what_the_mark_stood_for_leaves_out_a_port_whose_mark_was_dismissed(con):
    """The message's count is the count on the server's page, and the page
    does not count a port whose mark a person dismissed
    (`cvedismiss.is_dismissed`)."""
    from app import cvedismiss
    cvedismiss.init(con)
    server(con, "web-07")
    look(con)
    assert cvedismiss.set_dismissed(con, "web-07", "tcp", 80, True, now=NOW, extract_for=extracts(FIRST))
    [batch] = look(con, LATER)
    [one] = batch.told
    assert one.ports == (("tcp", 22),) and one.cves == ("CVE-2026-00003",)
    # Port 22's two, and not port 80's one.
    assert one.marked == ("CVE-2026-00001", "CVE-2026-00003")
    # What is left is OpenSSH alone, whose lists offer every fix.
    assert one.mark_offered is True


def test_a_revoked_server_is_told_about_no_more(con):
    web = server(con, "web-07")
    look(con)
    store.revoke_host(con, "web-07")
    assert look(con, LATER) == []
    assert ("tcp", 22, "CVE-2026-00003") not in told(con, web)


# ------------------------------------------------------- one workspace

def test_every_server_of_a_workspace_is_in_one_batch(con):
    server(con, "web-07")
    server(con, "db-02")
    look(con)
    [batch] = look(con, LATER)
    assert [one.host_name for one in batch.told] == ["db-02", "web-07"]


def test_one_workspace_is_never_told_about_anothers_servers(con):
    other = db.create_workspace(con, "another")
    server(con, "web-07")
    server(con, "their-box", workspace_id=other)
    look(con)
    batches = look(con, LATER)
    assert sorted((b.workspace_id, [one.host_name for one in b.told]) for b in batches) == [
        (db.DEFAULT_WORKSPACE_ID, ["web-07"]), (other, ["their-box"])]


# ---------------------------------------------------------- what is kept

def test_what_is_kept_is_the_server_the_port_and_the_cve_and_nothing_else(con):
    """No package, no version, no text out of a report: a match is worked
    out each time and kept nowhere. What is kept is what telling once needs."""
    server(con, "web-07")
    look(con)
    look(con, LATER)
    columns = {table: [row[1] for row in con.execute(f"PRAGMA table_info({table})")]
               for table in ("cve_started", "cve_told", "cve_batches")}
    assert columns == {"cve_started": ["host_id", "protocol", "port", "started_at"],
                       "cve_told": ["host_id", "protocol", "port", "cve", "told_at", "batch_id"],
                       "cve_batches": ["id", "workspace_id", "created_at", "told"]}
    everything = json.dumps([list(row) for table in columns for row in con.execute(f"SELECT * FROM {table}")])
    for kept_nowhere in ("openssh", "nginx", "deb12", "1.22.1", "ssh.service", "/usr/sbin"):
        assert kept_nowhere not in everything, kept_nowhere


def test_a_deleted_server_takes_its_rows_along(con):
    web = server(con, "web-07")
    look(con)
    look(con, LATER)
    store.revoke_host(con, "web-07")
    assert store.delete_host(con, "web-07") is True
    for table in ("cve_started", "cve_told"):
        assert con.execute(f"SELECT COUNT(*) FROM {table} WHERE host_id = ?", (web,)).fetchone()[0] == 0


def test_a_batch_is_written_whole_or_not_at_all(con):
    """The rows that say a CVE was told and the batch that tells it are one
    transaction, so a crash between them cannot leave a CVE marked told that
    no message carries."""
    web = server(con, "web-07")
    look(con)
    [batch_id] = cvetell.evaluate(con, now=NOW, extract_for=extracts(LATER))
    marked = con.execute("SELECT COUNT(*) FROM cve_told WHERE batch_id = ?", (batch_id,)).fetchone()[0]
    assert marked == 1 and cvetell.batch(con, batch_id).told[0].host_id == web
