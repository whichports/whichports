"""A person dismissing the CVE check's mark on one port of one server.

    python -m pytest tests/test_cvedismiss.py

`docs/RECORD.md` 4.338: the mark can be dismissed. A dismissal belongs to
the port and to the CVEs the mark stood for at that moment, so it says "I
know about these" and not "never tell me about this port": a CVE that joins
the set later brings the mark back.
"""
from datetime import datetime, timezone

import pytest

from app import alerts, cvecard, cvedismiss, db, finding_alerts, intent, store
from test_cvetell import FIRST, LATER, extracts, report, reports

NOW = datetime(2026, 10, 4, 9, 0, tzinfo=timezone.utc)


@pytest.fixture
def con(tmp_path):
    con = db.connect(str(tmp_path / "cp.db"))
    for module in (db, intent, alerts, finding_alerts, cvedismiss):
        module.init(con)
    return con


def server(con, name="web-07", workspace_id=db.DEFAULT_WORKSPACE_ID):
    host_id, _ = store.add_host(con, name, workspace_id=workspace_id)
    reports(con, host_id, report())
    return host_id


def dismiss(con, port, wanted=True, rows=FIRST, name="web-07", workspace_id=None):
    return cvedismiss.set_dismissed(con, name, "tcp", port, wanted, workspace_id=workspace_id,
                                    now=NOW, extract_for=extracts(rows))


def stored(con):
    return sorted(tuple(row) for row in con.execute("SELECT protocol, port, cve FROM cve_dismissed"))


def cards(con, host_id, rows):
    import json
    doc = json.loads(store.latest_report(con, host_id)["document"])
    return cvecard.cards_of(doc, extracts(rows), NOW)


def test_dismissing_writes_down_the_cves_the_mark_stands_for_as_the_server_sees_them(con):
    """The request names a port and nothing else. Which CVEs the mark stands
    for is worked out here, from the newest report and the release's data."""
    server(con)
    assert dismiss(con, 22) is True
    assert stored(con) == [("tcp", 22, "CVE-2026-00001")]
    assert cvedismiss.dismissed_by_host(con) == {"web-07": {("tcp", 22): frozenset({"CVE-2026-00001"})}}


def test_a_dismissed_mark_is_gone_and_a_cve_that_joins_later_brings_it_back(con):
    web = server(con)
    dismiss(con, 22)
    known = cvedismiss.dismissed_by_host(con)["web-07"]
    assert cvedismiss.is_dismissed(cards(con, web, FIRST)[("tcp", 22)], known.get(("tcp", 22)))
    assert not cvedismiss.is_dismissed(cards(con, web, LATER)[("tcp", 22)], known.get(("tcp", 22)))
    # Dismissed again, it stands for both.
    dismiss(con, 22, rows=LATER)
    known = cvedismiss.dismissed_by_host(con)["web-07"]
    assert cvedismiss.is_dismissed(cards(con, web, LATER)[("tcp", 22)], known.get(("tcp", 22)))


def test_another_port_of_the_server_keeps_its_mark(con):
    web = server(con)
    dismiss(con, 22)
    known = cvedismiss.dismissed_by_host(con)["web-07"]
    assert not cvedismiss.is_dismissed(cards(con, web, FIRST)[("tcp", 80)], known.get(("tcp", 80)))


def test_a_port_with_no_mark_has_nothing_dismissed():
    assert not cvedismiss.is_dismissed(cvecard.Card(lines=()), frozenset({"CVE-2026-00001"}))
    assert not cvedismiss.is_dismissed(cvecard.Card(lines=(), mark="x", cves=("CVE-2026-00001",)), None)


def test_restore_brings_the_mark_back_and_keeps_nothing(con):
    server(con)
    dismiss(con, 22)
    assert dismiss(con, 22, wanted=False) is False
    assert stored(con) == [] and cvedismiss.dismissed_by_host(con) == {}
    assert dismiss(con, 22, wanted=False) is False, "restoring what is not dismissed is no error"


def test_dismissing_twice_keeps_the_first_time(con):
    server(con)
    dismiss(con, 22)
    first = con.execute("SELECT dismissed_at FROM cve_dismissed").fetchone()[0]
    cvedismiss.set_dismissed(con, "web-07", "tcp", 22, True, extract_for=extracts(FIRST),
                             now=datetime(2026, 10, 5, 9, 0, tzinfo=timezone.utc))
    assert con.execute("SELECT dismissed_at FROM cve_dismissed").fetchone()[0] == first


def test_a_port_that_carries_no_mark_cannot_be_dismissed(con):
    server(con)
    for port, why in ((9999, "no socket"), (22, "no data")):
        with pytest.raises(cvedismiss.DismissError, match="no mark to dismiss"):
            cvedismiss.set_dismissed(con, "web-07", "tcp", port, True, now=NOW,
                                     extract_for=extracts(FIRST) if why == "no socket" else lambda *_: None)
    assert stored(con) == []


@pytest.mark.parametrize("protocol,port,wanted,why", [
    (6, 22, True, "not a port"), ("tcp", "22", True, "not a port"), ("tcp", True, True, "not a port"),
    ("tcp", 22, "yes", "true or false"), ("tcp", 22, None, "true or false"), ("tcp", 22, 1, "true or false")])
def test_what_is_not_a_port_or_not_a_yes_or_no_is_refused(con, protocol, port, wanted, why):
    server(con)
    with pytest.raises(cvedismiss.DismissError, match=why):
        cvedismiss.set_dismissed(con, "web-07", protocol, port, wanted, now=NOW, extract_for=extracts(FIRST))


def test_an_unknown_server_a_removed_one_and_another_workspaces_answer_alike(con):
    other = db.create_workspace(con, "another")
    server(con)
    server(con, "their-box", workspace_id=other)
    assert dismiss(con, 22, name="nothing-here") is None
    assert dismiss(con, 22, name="their-box", workspace_id=db.DEFAULT_WORKSPACE_ID) is None
    store.revoke_host(con, "web-07")
    assert dismiss(con, 22) is None
    assert stored(con) == []
    # One workspace is never shown another's dismissals.
    assert dismiss(con, 22, name="their-box", workspace_id=other) is True
    assert cvedismiss.dismissed_by_host(con, workspace_id=db.DEFAULT_WORKSPACE_ID) == {}
    assert list(cvedismiss.dismissed_by_host(con, workspace_id=other)) == ["their-box"]


def test_a_database_from_before_dismissals_has_none(tmp_path):
    con = db.connect(str(tmp_path / "old.db"))
    db.init(con)
    assert cvedismiss.dismissed_by_host(con) == {}


def test_a_deleted_server_takes_its_dismissals_along(con):
    web = server(con)
    dismiss(con, 22)
    store.revoke_host(con, "web-07")
    assert store.delete_host(con, "web-07") is True
    assert con.execute("SELECT COUNT(*) FROM cve_dismissed WHERE host_id = ?", (web,)).fetchone()[0] == 0
