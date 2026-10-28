"""The daily job that brings the CVE extracts up to date.

    python -m pytest tests/test_cvesync_cli.py

No request is made: the fetch is handed in, and answers with files written
for the tests in the vendors' shapes.
"""
import gzip
import io
import json
import tarfile
from datetime import datetime, timezone

import pytest

from app import cveextract, cvefetch, cvestore, cvesync_cli, db, store
from app.cveextract import Header, Row

TRACKER_TIME = "2026-10-03T14:07:28Z"
TARBALL_TIME = "2026-10-02T18:10:09Z"
OURS = "https://data.whichports.test/cve"

TRACKER = {"openssh": {
    "CVE-2025-00001": {"releases": {
        "bookworm": {"status": "resolved", "fixed_version": "1:9.2p1-2+deb12u5", "urgency": "low"},
        "trixie": {"status": "resolved", "fixed_version": "1:10.0p1-7", "urgency": "low"}}},
    "CVE-2025-00002": {"releases": {
        "bookworm": {"status": "open", "urgency": "unimportant"}}},
}}

RECORD = {"id": "UBUNTU-CVE-2025-00001", "upstream": ["CVE-2025-00001"],
          "severity": [{"type": "Ubuntu", "score": "medium"}],
          "affected": [{"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "openssh"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [
                            {"introduced": "0"}, {"fixed": "1:9.6p1-3ubuntu13.5"}]}]}]}


def tarball(records):
    held = io.BytesIO()
    with tarfile.open(fileobj=held, mode="w:xz") as archive:
        for number, record in enumerate(records):
            data = json.dumps(record).encode()
            info = tarfile.TarInfo(f"osv/cve/2025/UBUNTU-CVE-2025-{number:05d}.json")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return held.getvalue()


class Vendors:
    """A stand-in for cvefetch.fetch: answers by address, keeps what was asked."""

    def __init__(self, answers):
        self.answers = answers
        self.asked = []

    def __call__(self, url, allowed_hosts, max_bytes, resolver=None, opener=None, headers=None):
        self.asked.append((url, tuple(allowed_hosts), max_bytes, headers))
        answer = self.answers[url]
        if isinstance(answer, Exception):
            raise answer
        return answer


def vendors(tracker=TRACKER, records=(RECORD,)):
    return Vendors({
        cvefetch.DEBIAN_TRACKER_URL: (gzip.compress(json.dumps(tracker).encode()), TRACKER_TIME),
        cvefetch.UBUNTU_OSV_URL: (tarball(records), TARBALL_TIME),
    })


@pytest.fixture()
def con(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    connection = db.connect()
    db.init(connection)
    yield connection
    connection.close()


def reporting(con, name, distribution):
    """A server whose newest report says which distribution it runs."""
    host_id, _credential = store.add_host(con, name)
    document = {"hostname": name, "packages": {"status": "collected", "distribution": distribution}}
    store.insert_report(con, host_id, 1, 1, json.dumps(document))
    return host_id


# -------------------------------------------------------------------- build

def test_build_fetches_both_vendors_files_and_writes_every_releases_extract(tmp_path):
    fetch = vendors()
    morning = datetime(2026, 10, 4, 4, 41, tzinfo=timezone.utc)
    lines = cvesync_cli.build(tmp_path / "out", fetch=fetch, now=morning)
    assert [(url, hosts) for url, hosts, _cap, _headers in fetch.asked] == [
        (cvefetch.DEBIAN_TRACKER_URL, cvefetch.VENDOR_HOSTS),
        (cvefetch.UBUNTU_OSV_URL, cvefetch.VENDOR_HOSTS)]
    assert fetch.asked[0][2:] == (cvefetch.MAX_TRACKER_BYTES, {"Accept-Encoding": "gzip"})
    assert fetch.asked[1][2] == cvefetch.MAX_TARBALL_DOWNLOAD_BYTES
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == [
        "debian-12.tsv.gz", "debian-13.tsv.gz", "ubuntu-24.04.tsv.gz", "ubuntu-26.04.tsv.gz"]
    stored = cvestore.read("debian", "12", where=tmp_path / "out")
    assert stored.header == Header("debian", "12", True, TRACKER_TIME, "2026-10-04T04:41:00Z")
    assert stored.by_source == {"openssh": (Row("openssh", "CVE-2025-00001", "1:9.2p1-2+deb12u5", "low"),)}
    assert cvestore.read("ubuntu", "24.04", where=tmp_path / "out").header.source_modified == TARBALL_TIME
    assert cvestore.read("ubuntu", "26.04", where=tmp_path / "out").by_source == {}
    assert lines[0].startswith("debian 12: 1 rows, ")
    assert "vendor's file of 2026-10-03T14:07:28Z" in lines[0]
    assert lines[2].startswith("ubuntu 24.04: 1 rows, ")


def test_build_stamps_each_extract_with_when_it_was_built_and_keeps_the_vendors_own_time(tmp_path):
    """Two facts: when the vendor last changed its file, and when this job
    last fetched it. A card counts its three days from the second."""
    morning = datetime(2026, 10, 12, 4, 41, 7, tzinfo=timezone.utc)
    cvesync_cli.build(tmp_path, fetch=vendors(), now=morning)
    for distribution, version_id in (("debian", "12"), ("ubuntu", "24.04")):
        header = cvestore.read(distribution, version_id, where=tmp_path).header
        assert header.built == "2026-10-12T04:41:07Z", (distribution, header)
    assert cvestore.read("ubuntu", "24.04", where=tmp_path).header.source_modified == TARBALL_TIME


def test_build_with_the_switch_the_other_way_keeps_what_no_update_fixes(tmp_path):
    cvesync_cli.build(tmp_path, only_fixable=False, fetch=vendors())
    stored = cvestore.read("debian", "12", where=tmp_path)
    assert stored.header.only_fixable is False
    assert [row.cve for row in stored.by_source["openssh"]] == ["CVE-2025-00001", "CVE-2025-00002"]


@pytest.mark.parametrize("broken", [cvefetch.DEBIAN_TRACKER_URL, cvefetch.UBUNTU_OSV_URL])
def test_a_vendor_that_cannot_be_fetched_leaves_every_extract_as_it_was(tmp_path, broken, capsys):
    """Every extract is built before the first is written."""
    cvesync_cli.build(tmp_path, fetch=vendors())
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    fetch = vendors(tracker={"nginx": {}})
    fetch.answers[broken] = cvefetch.FetchError(cvefetch.NOT_REACHED, "URLError")
    code = cvesync_cli.main(["build", "--out", str(tmp_path)], fetch=fetch)
    assert code == cvesync_cli.EXIT_FAILED
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before
    assert "not updated" in capsys.readouterr().err


def test_a_tracker_that_is_not_json_or_not_a_tracker_is_refused_and_nothing_written(tmp_path):
    for body in (b"<html>maintenance</html>", gzip.compress(b"[1, 2]")):
        fetch = vendors()
        fetch.answers[cvefetch.DEBIAN_TRACKER_URL] = (body, TRACKER_TIME)
        assert cvesync_cli.main(["build", "--out", str(tmp_path / "out")], fetch=fetch
                                ) == cvesync_cli.EXIT_FAILED
        assert not (tmp_path / "out").exists() or list((tmp_path / "out").iterdir()) == []


def test_a_tarball_that_is_no_tarball_is_refused_and_nothing_written(tmp_path):
    fetch = vendors()
    fetch.answers[cvefetch.UBUNTU_OSV_URL] = (b"not a tarball", TARBALL_TIME)
    assert cvesync_cli.main(["build", "--out", str(tmp_path / "out")], fetch=fetch
                            ) == cvesync_cli.EXIT_FAILED
    assert not (tmp_path / "out").exists() or list((tmp_path / "out").iterdir()) == []


# ----------------------------------------------------------------- releases

def test_the_releases_in_use_are_read_from_each_servers_newest_report(con):
    reporting(con, "web", {"id": "debian", "version_id": "12", "version_codename": "bookworm"})
    reporting(con, "db", {"id": "debian", "version_id": "12"})
    reporting(con, "app", {"id": "ubuntu", "version_id": "24.04"})
    reporting(con, "old", {"id": "debian", "version_id": "11"})      # no extract exists for it
    reporting(con, "alma", {"id": "almalinux", "version_id": "10"})
    assert cvesync_cli.releases_in_use(con) == [("debian", "12"), ("ubuntu", "24.04")]


def test_a_removed_server_a_silent_one_and_a_report_without_the_section_count_for_nothing(con):
    gone = reporting(con, "gone", {"id": "debian", "version_id": "13"})
    con.execute("UPDATE hosts SET revoked_at = 'x' WHERE id = ?", (gone,))
    store.add_host(con, "never-reported")
    quiet, _credential = store.add_host(con, "before-the-section")
    store.insert_report(con, quiet, 1, 1, json.dumps({"hostname": "before-the-section"}))
    broken, _credential = store.add_host(con, "broken")
    store.insert_report(con, broken, 1, 1, "not a document")
    con.commit()
    assert cvesync_cli.releases_in_use(con) == []


def test_only_the_newest_report_of_a_server_counts(con):
    host_id = reporting(con, "upgraded", {"id": "debian", "version_id": "12"})
    store.insert_report(con, host_id, 2, 1, json.dumps(
        {"packages": {"status": "collected", "distribution": {"id": "debian", "version_id": "13"}}}))
    assert cvesync_cli.releases_in_use(con) == [("debian", "13")]


# -------------------------------------------------------------------- fetch

def ours(*releases):
    answers = {}
    for distribution, version_id in releases:
        rows = [Row("openssh", "CVE-2025-00001", "1:9.2p1-2+deb12u5", "")]
        answers[f"{OURS}/{distribution}-{version_id}.tsv.gz"] = (
            cveextract.dump(rows, distribution, version_id, source_modified=TRACKER_TIME), "")
    return Vendors(answers)


def test_fetch_asks_our_host_for_each_release_named_and_puts_it_in_place(tmp_path):
    fetch = ours(("debian", "12"), ("ubuntu", "24.04"))
    lines, failed = cvesync_cli.fetch_extracts(OURS + "/", [("debian", "12"), ("ubuntu", "24.04")],
                                               tmp_path, fetch)
    assert failed == 0
    assert [(url, hosts, cap) for url, hosts, cap, _h in fetch.asked] == [
        (OURS + "/debian-12.tsv.gz", ("data.whichports.test",), cvefetch.MAX_EXTRACT_DOWNLOAD_BYTES),
        (OURS + "/ubuntu-24.04.tsv.gz", ("data.whichports.test",), cvefetch.MAX_EXTRACT_DOWNLOAD_BYTES)]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["debian-12.tsv.gz", "ubuntu-24.04.tsv.gz"]
    assert lines == ["debian 12: updated, vendor's file of 2026-10-03T14:07:28Z",
                     "ubuntu 24.04: updated, vendor's file of 2026-10-03T14:07:28Z"]


def test_a_release_that_fails_keeps_yesterdays_file_and_the_others_still_update(tmp_path):
    cvesync_cli.fetch_extracts(OURS, [("debian", "12")], tmp_path, ours(("debian", "12")))
    yesterday = (tmp_path / "debian-12.tsv.gz").read_bytes()
    fetch = ours(("ubuntu", "24.04"))
    fetch.answers[OURS + "/debian-12.tsv.gz"] = cvefetch.FetchError(cvefetch.BAD_STATUS, "503")
    lines, failed = cvesync_cli.fetch_extracts(OURS, [("debian", "12"), ("ubuntu", "24.04")],
                                               tmp_path, fetch)
    assert failed == 1
    assert (tmp_path / "debian-12.tsv.gz").read_bytes() == yesterday
    assert (tmp_path / "ubuntu-24.04.tsv.gz").exists()
    assert lines[0] == "debian 12: not updated, the host did not answer 200: 503"


def test_a_file_served_under_one_releases_name_that_is_anothers_is_not_put_in_place(tmp_path):
    fetch = ours(("debian", "12"))
    fetch.answers[OURS + "/debian-13.tsv.gz"] = fetch.answers[OURS + "/debian-12.tsv.gz"]
    lines, failed = cvesync_cli.fetch_extracts(OURS, [("debian", "13")], tmp_path, fetch)
    assert failed == 1 and list(tmp_path.iterdir()) == []
    assert lines[0].startswith("debian 13: not updated, ")


def test_a_damaged_download_is_not_put_in_place(tmp_path):
    fetch = ours(("debian", "12"))
    whole, _time = fetch.answers[OURS + "/debian-12.tsv.gz"]
    fetch.answers[OURS + "/debian-12.tsv.gz"] = (whole[:-9], "")
    _lines, failed = cvesync_cli.fetch_extracts(OURS, [("debian", "12")], tmp_path, fetch)
    assert failed == 1 and list(tmp_path.iterdir()) == []


# -------------------------------------------------------------------- daily

def env(tmp_path, **more):
    out = {db.DB_ENV: str(tmp_path / "test.db"), cvestore.DIR_ENV: str(tmp_path / "cve")}
    out.update(more)
    return out


def test_daily_does_nothing_and_says_so_when_the_setting_is_not_set(con, tmp_path, capsys):
    never = Vendors({})
    assert cvesync_cli.main(["daily"], env=env(tmp_path), fetch=never) == cvesync_cli.EXIT_OK
    assert never.asked == []
    assert "nothing fetched" in capsys.readouterr().out
    assert cvesync_cli.main(["daily"], env=env(tmp_path, WHICHPORTS_CVE_DATA="everything"),
                            fetch=never) == cvesync_cli.EXIT_OK
    assert never.asked == []


def test_daily_from_us_fetches_only_the_releases_this_instance_runs(con, tmp_path, capsys):
    reporting(con, "web", {"id": "debian", "version_id": "12"})
    fetch = ours(("debian", "12"), ("debian", "13"), ("ubuntu", "24.04"))
    code = cvesync_cli.main(["daily"], fetch=fetch,
                            env=env(tmp_path, WHICHPORTS_CVE_DATA="whichports", WHICHPORTS_CVE_URL=OURS))
    assert code == cvesync_cli.EXIT_OK
    assert [url for url, *_rest in fetch.asked] == [OURS + "/debian-12.tsv.gz"]
    assert [p.name for p in (tmp_path / "cve").iterdir()] == ["debian-12.tsv.gz"]


def test_daily_from_us_with_no_address_set_fetches_nothing_and_fails(con, tmp_path, capsys):
    never = Vendors({})
    assert cvesync_cli.main(["daily"], fetch=never, env=env(tmp_path, WHICHPORTS_CVE_DATA="whichports")
                            ) == cvesync_cli.EXIT_FAILED
    assert never.asked == []
    assert "WHICHPORTS_CVE_URL is not set" in capsys.readouterr().err


def test_daily_with_no_server_on_a_known_release_asks_for_nothing(con, tmp_path, capsys):
    never = Vendors({})
    code = cvesync_cli.main(["daily"], fetch=never,
                            env=env(tmp_path, WHICHPORTS_CVE_DATA="whichports", WHICHPORTS_CVE_URL=OURS))
    assert code == cvesync_cli.EXIT_OK and never.asked == []


def test_daily_from_the_vendors_builds_into_the_instances_own_store(con, tmp_path):
    fetch = vendors()
    code = cvesync_cli.main(["daily"], fetch=fetch, env=env(tmp_path, WHICHPORTS_CVE_DATA="vendors"))
    assert code == cvesync_cli.EXIT_OK
    assert sorted(p.name for p in (tmp_path / "cve").iterdir()) == [
        "debian-12.tsv.gz", "debian-13.tsv.gz", "ubuntu-24.04.tsv.gz", "ubuntu-26.04.tsv.gz"]
    assert [url for url, *_rest in fetch.asked] == [cvefetch.DEBIAN_TRACKER_URL, cvefetch.UBUNTU_OSV_URL]


def test_the_command_needs_to_be_told_which_of_the_three_it_is():
    with pytest.raises(SystemExit) as stopped:
        cvesync_cli.main([])
    assert stopped.value.code == cvesync_cli.EXIT_USAGE
    with pytest.raises(SystemExit):
        cvesync_cli.main(["build"])
    with pytest.raises(SystemExit):
        cvesync_cli.main(["fetch"])
