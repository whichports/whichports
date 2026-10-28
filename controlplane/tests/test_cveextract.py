"""The slim CVE extract: what the builder takes from the vendors' files, what
it leaves out and counts, the one switch, and the file it writes.

    python -m pytest tests/test_cveextract.py

The entries here are written for the tests in the shape the two vendors
publish (Debian's security tracker JSON and Canonical's OSV records, both
read on 2026-10-03). None is a copy of a published record: the CVE numbers
are made up, and Canonical's data is CC-BY-SA.

Run on the two real files that day, the builder gave, every row and only the
rows an update fixes: Debian 12 54,902 and 43,834, Debian 13 56,814 and
49,681, Ubuntu 24.04 471,336 and 116,471, Ubuntu 26.04 86,431 and 25,040.
Every extract read back as the rows it was built from. For openssh on Debian
12 it gave 106 rows, 86 with a fix and 20 without, the 20 that 4.280 counted
by hand.
"""
import gzip
import io
import json
import tarfile

import pytest

from app import cveextract, cveextract_cli
from app.cveextract import (ExtractError, Header, Row, debian_rows, dump, load, select,
                            ubuntu_records, ubuntu_rows)

NOBLE = "Ubuntu:24.04:LTS"
TRACKER_TIME = "2026-10-03T14:07:28Z"


# ------------------------------------------------------------------ Debian

def entry(status="resolved", fixed="1:9.2p1-2+deb12u5", urgency="not yet assigned", **more):
    out = {"status": status, "repositories": {"bookworm": "1:9.2p1-2+deb12u10"},
           "urgency": urgency}
    if fixed is not None:
        out["fixed_version"] = fixed
    out.update(more)
    return out


def tracker(issues, source="openssh"):
    """One source package's issues, each {id: bookworm entry}."""
    return {source: {ident: {"description": "written for a test",
                             "releases": {"bookworm": value}}
                     for ident, value in issues.items()}}


def test_a_resolved_issue_is_a_row_with_the_version_that_fixes_it():
    rows, left_out = debian_rows(tracker({"CVE-2025-00001": entry(urgency="low")}), "bookworm")
    assert rows == [Row("openssh", "CVE-2025-00001", "1:9.2p1-2+deb12u5", "low")]
    assert left_out == {}


def test_an_open_issue_is_a_row_with_no_fixed_version():
    rows, left_out = debian_rows(
        tracker({"CVE-2025-00002": entry("open", fixed=None, urgency="unimportant")}), "bookworm")
    assert rows == [Row("openssh", "CVE-2025-00002", "", "unimportant")]
    assert left_out == {}


def test_a_fixed_version_of_zero_means_the_release_never_had_it():
    """14,799 of the resolved entries in bookworm and trixie on 2026-10-03."""
    rows, left_out = debian_rows(tracker({"CVE-2025-00003": entry(fixed="0")}), "bookworm")
    assert rows == []
    assert left_out == {cveextract.NOT_AFFECTED: 1}


def test_an_undetermined_issue_is_left_out_and_counted():
    """Debian's own word for an issue somebody still has to look at. Counting
    it on a port would say more than Debian does."""
    rows, left_out = debian_rows(
        tracker({"CVE-2025-00004": entry("undetermined", fixed=None)}), "bookworm")
    assert rows == []
    assert left_out == {cveextract.UNDETERMINED: 1}


def test_an_id_that_is_no_cve_is_left_out_and_counted():
    rows, left_out = debian_rows(tracker({"TEMP-0331720-9168FE": entry()}), "bookworm")
    assert rows == []
    assert left_out == {cveextract.NOT_A_CVE: 1}


def test_an_issue_with_no_entry_for_the_release_is_nothing_at_all():
    rows, left_out = debian_rows(tracker({"CVE-2025-00005": entry()}), "trixie")
    assert rows == [] and left_out == {}


def test_each_release_gets_its_own_answer():
    data = {"nginx": {"CVE-2025-00006": {"releases": {
        "bookworm": entry("open", fixed=None, urgency="unimportant"),
        "trixie": entry(fixed="1.24.0-2", urgency="unimportant")}}}}
    assert debian_rows(data, "bookworm")[0] == [Row("nginx", "CVE-2025-00006", "", "unimportant")]
    assert debian_rows(data, "trixie")[0] == [
        Row("nginx", "CVE-2025-00006", "1.24.0-2", "unimportant")]


def test_a_fixed_version_that_is_no_version_is_not_guessed_at():
    """Debian's own file held one on 2026-10-03, "1:0.23.0+dfsg-", in trixie."""
    rows, left_out = debian_rows(
        tracker({"CVE-2025-00007": entry(fixed="1:0.23.0+dfsg-")}), "bookworm")
    assert rows == []
    assert left_out == {cveextract.NOT_UNDERSTOOD: 1}


@pytest.mark.parametrize("value", [
    entry("resolved", fixed=None),            # resolved, and no version named
    entry("resolved", fixed=""),
    entry("resolved", fixed=12),
    entry("open", fixed="1:9.2p1-2+deb12u5"),  # open, and yet a version
    entry("fixed"),                           # a status the tracker does not use
    entry(status=None),
    "resolved",                               # not an entry at all
    None,
])
def test_an_entry_in_a_shape_not_measured_is_left_out_and_counted(value):
    rows, left_out = debian_rows(tracker({"CVE-2025-00008": value}), "bookworm")
    if value is None:
        # No entry for the release is the package not being in it.
        assert rows == [] and left_out == {}
    else:
        assert rows == []
        assert left_out == {cveextract.NOT_UNDERSTOOD: 1}


def test_a_new_urgency_word_keeps_the_row_and_is_counted():
    rows, left_out = debian_rows(tracker({"CVE-2025-00009": entry(urgency="severe")}), "bookworm")
    assert rows == [Row("openssh", "CVE-2025-00009", "1:9.2p1-2+deb12u5", "")]
    assert left_out == {cveextract.URGENCY_NOT_KNOWN: 1}


@pytest.mark.parametrize("source", ["OpenSSH", "o", "open ssh", "openssh\t", "openssh\n", ""])
def test_a_source_package_name_outside_debians_rule_is_left_out(source):
    rows, left_out = debian_rows(tracker({"CVE-2025-00010": entry()}, source=source), "bookworm")
    assert rows == []
    assert left_out == {cveextract.NOT_UNDERSTOOD: 1}


@pytest.mark.parametrize("data", [
    {"openssh": "not a table of issues"},
    {"openssh": {"CVE-2025-00011": "not an issue"}},
    {"openssh": {"CVE-2025-00011": {"description": "no releases"}}},
])
def test_a_package_or_an_issue_that_is_not_one_is_counted(data):
    rows, left_out = debian_rows(data, "bookworm")
    assert rows == []
    assert left_out == {cveextract.NOT_UNDERSTOOD: 1}


def test_a_tracker_that_is_not_an_object_is_refused():
    with pytest.raises(ExtractError):
        debian_rows(["openssh"], "bookworm")


def test_the_rows_come_sorted_by_package_then_cve():
    data = tracker({"CVE-2025-00020": entry(), "CVE-2025-00012": entry()})
    data.update(tracker({"CVE-2025-00030": entry(fixed="1.22.1-9+deb12u1")}, source="nginx"))
    assert [(r.source, r.cve) for r in debian_rows(data, "bookworm")[0]] == [
        ("nginx", "CVE-2025-00030"), ("openssh", "CVE-2025-00012"), ("openssh", "CVE-2025-00020")]


# ------------------------------------------------------------------ Ubuntu

def affected(name="openssh", ecosystem=NOBLE, fixed="1:9.6p1-3ubuntu13.5", **more):
    events = [{"introduced": "0"}]
    if fixed is not None:
        events.append({"fixed": fixed})
    out = {"package": {"ecosystem": ecosystem, "name": name},
           "ranges": [{"type": "ECOSYSTEM", "events": events}], "versions": []}
    out.update(more)
    return out


def record(ident="UBUNTU-CVE-2025-00001", upstream=("CVE-2025-00001",), priority="medium",
           entries=None, **more):
    # A string is left a string, for the test of an `upstream` that is no list.
    out = {"id": ident, "upstream": upstream if isinstance(upstream, str) else list(upstream),
           "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
           "affected": [affected()] if entries is None else list(entries)}
    if priority is not None:
        out["severity"].append({"type": "Ubuntu", "score": priority})
    out.update(more)
    return out


def test_a_patched_package_is_a_row_with_its_fixed_version_and_canonicals_priority():
    """Canonical: "Whenever the team patches a vulnerability, the source
    package version is listed in fixed"."""
    rows, left_out = ubuntu_rows([record()], NOBLE)
    assert rows == [Row("openssh", "CVE-2025-00001", "1:9.6p1-3ubuntu13.5", "medium")]
    assert left_out == {}


def test_a_package_with_no_fixed_version_is_a_row_with_none():
    """Needs evaluation and vulnerable alike: "Listed under affected and
    fixed is not set"."""
    rows, _left_out = ubuntu_rows([record(entries=[affected(fixed=None)])], NOBLE)
    assert rows == [Row("openssh", "CVE-2025-00001", "", "medium")]


def test_only_the_release_asked_for_is_taken_and_never_a_pro_stream():
    entries = [affected(ecosystem="Ubuntu:22.04:LTS", fixed="1:8.9p1-3ubuntu0.13"),
               affected(ecosystem="Ubuntu:Pro:24.04:LTS", fixed="1:9.6p1-3ubuntu13.99"),
               affected(fixed="1:9.6p1-3ubuntu13.5")]
    rows, left_out = ubuntu_rows([record(entries=entries)], NOBLE)
    assert rows == [Row("openssh", "CVE-2025-00001", "1:9.6p1-3ubuntu13.5", "medium")]
    assert left_out == {}


def test_a_fix_only_ubuntu_pro_offers_is_no_fix_for_the_extract():
    """A fix a server can get only with Ubuntu Pro is, for a server without
    it, no update at all. It may reach this data two ways. Pro's own data set
    has a name of its own and is never read, which the test above holds. And
    under a release's plain name a fixed version can carry Pro's own mark,
    `~esm1` or `+esm1`: Canonical's data of 2026-10-02 holds such versions
    under 16.04 and 18.04, and none under 24.04. So a fixed version with
    that mark counts as no fixed version, and is counted, and a port is never
    told of a fix its server's lists cannot offer."""
    entries = [affected(name="openssh", fixed="1:9.6p1-3ubuntu13.5"),
               affected(name="vlc", fixed="3.0.20-3ubuntu0.1~esm1"),
               affected(name="libxml2", fixed="2.9.14+dfsg-1.3ubuntu3+esm2")]
    rows, left_out = ubuntu_rows([record(entries=entries)], NOBLE)
    assert {r.source: r.fixed for r in rows} == {
        "openssh": "1:9.6p1-3ubuntu13.5", "vlc": "", "libxml2": ""}
    assert left_out == {cveextract.PRO_ONLY: 2}
    # A version that only holds those three letters is not Pro's.
    rows, left_out = ubuntu_rows([record(entries=[affected(name="esmtp", fixed="1.2-18esm")])], NOBLE)
    assert [r.fixed for r in rows] == ["1.2-18esm"] and left_out == {}


def test_a_withdrawn_record_is_left_out_whole_and_counted_once():
    """Canonical: "we use the withdrawn field to indicate that the CVE record
    has been removed". 3,643 records on 2026-10-02."""
    withdrawn = record(entries=[affected(), affected(name="nginx", fixed="1.24.0-2ubuntu7.5")],
                       withdrawn="2026-09-30T00:00:00Z")
    rows, left_out = ubuntu_rows([withdrawn], NOBLE)
    assert rows == []
    assert left_out == {cveextract.WITHDRAWN: 1}


def test_a_record_that_names_no_cve_upstream_carries_it_in_its_own_id():
    rows, _left_out = ubuntu_rows([record("UBUNTU-CVE-2025-00042", upstream=())], NOBLE)
    assert [r.cve for r in rows] == ["CVE-2025-00042"]


@pytest.mark.parametrize("ident, upstream", [
    ("UBUNTU-CVE-2025-00001", ("CVE-2025-00001", "CVE-2025-00002")),  # two, so which
    ("USN-7548-1", ()),                                              # none anywhere
    ("UBUNTU-CVE-2025-00001", "CVE-2025-00001"),                     # not a list
    (None, ()),
])
def test_a_record_that_is_not_about_exactly_one_cve_is_left_out(ident, upstream):
    rows, left_out = ubuntu_rows([record(ident, upstream=upstream)], NOBLE)
    assert rows == []
    assert left_out == {cveextract.NOT_A_CVE: 1}


def test_a_record_with_no_priority_of_canonicals_has_none():
    rows, left_out = ubuntu_rows([record(priority=None)], NOBLE)
    assert [r.urgency for r in rows] == [""]
    assert left_out == {}


def test_a_new_priority_word_keeps_the_row_and_is_counted():
    rows, left_out = ubuntu_rows([record(priority="urgent")], NOBLE)
    assert [r.urgency for r in rows] == [""]
    assert left_out == {cveextract.URGENCY_NOT_KNOWN: 1}


@pytest.mark.parametrize("ranges", [
    [],                                                                     # none
    [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}] * 2,          # two
    [{"type": "SEMVER", "events": [{"introduced": "0"}]}],                 # another scheme
    [{"type": "ECOSYSTEM", "events": [{"introduced": "1:9.0p1-1"}]}],      # not from the start
    [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0-1"}, {"fixed": "1.0-2"}]}],
    [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": ""}]}],
    [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.0-1"}]}],
    [{"type": "ECOSYSTEM", "events": [{"fixed": "1.0-1"}, {"introduced": "0"}]}],
    [{"type": "ECOSYSTEM", "events": []}],
    "ECOSYSTEM",
])
def test_a_range_in_a_shape_canonical_does_not_document_is_not_guessed_at(ranges):
    entry_ = affected()
    entry_["ranges"] = ranges
    rows, left_out = ubuntu_rows([record(entries=[entry_])], NOBLE)
    assert rows == []
    assert left_out == {cveextract.NOT_UNDERSTOOD: 1}


@pytest.mark.parametrize("bad", [None, "a record", {"id": "UBUNTU-CVE-2025-00001"},
                                 {"id": "UBUNTU-CVE-2025-00001", "affected": "openssh"}])
def test_a_record_that_could_not_be_read_is_counted(bad):
    rows, left_out = ubuntu_rows([bad, record()], NOBLE)
    assert len(rows) == 1
    assert left_out == {cveextract.NOT_UNDERSTOOD: 1}


def test_the_same_row_twice_is_one_row():
    rows, left_out = ubuntu_rows([record(), record()], NOBLE)
    assert len(rows) == 1 and left_out == {}


def test_two_answers_for_one_package_and_cve_are_both_left_out():
    """Neither vendor's file held such a pair. Picking one would be a guess."""
    one = record(entries=[affected(fixed="1:9.6p1-3ubuntu13.5")])
    other = record(entries=[affected(fixed="1:9.6p1-3ubuntu13.9")])
    rows, left_out = ubuntu_rows([one, other, one], NOBLE)
    assert rows == []
    assert left_out == {cveextract.NOT_UNDERSTOOD: 3}


# ------------------------------------------------------------- the tarball

def tarball(tmp_path, members):
    path = tmp_path / "osv-all.tar.xz"
    with tarfile.open(path, "w:xz") as archive:
        for name, content in members:
            if content is None:
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
                continue
            data = content if isinstance(content, bytes) else json.dumps(content).encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def test_only_the_cve_records_of_the_tarball_are_read(tmp_path):
    path = tarball(tmp_path, [
        ("osv/cve/2025", None),
        ("osv/cve/2025/UBUNTU-CVE-2025-00001.json", record()),
        ("osv/usn/USN-7548-1.json", {"id": "USN-7548-1"}),
        ("osv/cve/2025/README", b"not a record"),
    ])
    assert [r["id"] for r in ubuntu_records(path)] == ["UBUNTU-CVE-2025-00001"]


def test_a_member_that_is_not_json_or_is_too_large_comes_back_as_none(tmp_path, monkeypatch):
    path = tarball(tmp_path, [
        ("osv/cve/2025/UBUNTU-CVE-2025-00001.json", b"{not json"),
        ("osv/cve/2025/UBUNTU-CVE-2025-00002.json", record("UBUNTU-CVE-2025-00002",
                                                           upstream=("CVE-2025-00002",))),
    ])
    assert [r if r is None else r["id"] for r in ubuntu_records(path)] == [
        None, "UBUNTU-CVE-2025-00002"]
    monkeypatch.setattr(cveextract, "MAX_RECORD_BYTES", 10)
    assert list(ubuntu_records(path)) == [None, None]


def test_a_tarball_whose_records_are_larger_than_one_is_refused(tmp_path, monkeypatch):
    """Canonical's 46 MB download held 11.2 GB of records on 2026-10-03. A
    file that unpacks to far more than that is not read to its end."""
    path = tarball(tmp_path, [
        ("osv/cve/2025/UBUNTU-CVE-2025-00001.json", record()),
        ("osv/cve/2025/UBUNTU-CVE-2025-00002.json", record("UBUNTU-CVE-2025-00002")),
    ])
    monkeypatch.setattr(cveextract, "MAX_TARBALL_BYTES", 600)
    with pytest.raises(ExtractError):
        list(ubuntu_records(path))


def test_the_tarball_may_be_an_open_file(tmp_path):
    path = tarball(tmp_path, [("osv/cve/2025/UBUNTU-CVE-2025-00001.json", record())])
    with open(path, "rb") as handle:
        assert [r["id"] for r in ubuntu_records(handle)] == ["UBUNTU-CVE-2025-00001"]


def test_several_releases_are_built_in_one_pass_over_the_records():
    """The records are read one at a time, so the builder is handed something
    it can walk once, and gives every release its own rows and counts."""
    other = "Ubuntu:26.04:LTS"
    records = iter([
        record(entries=[affected(), affected(ecosystem=other, fixed=None)]),
        record("UBUNTU-CVE-2025-00002", upstream=("CVE-2025-00002",), withdrawn="2026-09-30T00:00:00Z"),
        None,
    ])
    found = cveextract.ubuntu_rows_for(records, [NOBLE, other])
    assert found[NOBLE] == ([Row("openssh", "CVE-2025-00001", "1:9.6p1-3ubuntu13.5", "medium")],
                            {cveextract.WITHDRAWN: 1, cveextract.NOT_UNDERSTOOD: 1})
    assert found[other] == ([Row("openssh", "CVE-2025-00001", "", "medium")],
                            {cveextract.WITHDRAWN: 1, cveextract.NOT_UNDERSTOOD: 1})


@pytest.mark.parametrize("cut", [0, 40, 400])
def test_a_file_that_is_no_tarball_or_is_cut_is_refused_as_an_extract_error(tmp_path, cut):
    """Found by the daily command's test: tarfile raises an error of its own
    kind, which no caller of the builder catches."""
    whole = tarball(tmp_path, [("osv/cve/2025/UBUNTU-CVE-2025-%05d.json" % n,
                                record("UBUNTU-CVE-2025-%05d" % n)) for n in range(40)]).read_bytes()
    damaged = tmp_path / "damaged.tar.xz"
    damaged.write_bytes(b"not a tarball" if cut == 0 else whole[:cut])
    with pytest.raises(ExtractError):
        list(ubuntu_records(damaged))


def test_a_link_in_the_tarball_is_never_followed(tmp_path):
    path = tmp_path / "osv-all.tar.xz"
    with tarfile.open(path, "w:xz") as archive:
        info = tarfile.TarInfo("osv/cve/2025/UBUNTU-CVE-2025-00001.json")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        archive.addfile(info)
    assert list(ubuntu_records(path)) == []


# -------------------------------------------------------------- the switch

ROWS = [Row("nginx", "CVE-2025-00030", "", "unimportant"),
        Row("openssh", "CVE-2025-00001", "1:9.2p1-2+deb12u5", "low"),
        Row("openssh", "CVE-2025-00002", "", "not yet assigned")]


def test_the_switch_stands_at_only_what_an_update_fixes():
    """Decided 2026-10-03, question 6, answer (a) (docs/RECORD.md 4.285)."""
    assert cveextract.ONLY_FIXABLE is True
    assert select(ROWS) == [ROWS[1]]


def test_the_other_way_keeps_every_row():
    assert select(ROWS, only_fixable=False) == ROWS


def test_the_extract_follows_the_switch_unless_told_otherwise():
    header, rows = load(dump(ROWS, "debian", "12"))
    assert header.only_fixable is True and rows == [ROWS[1]]
    header, rows = load(dump(ROWS, "debian", "12", only_fixable=False))
    assert header.only_fixable is False and rows == ROWS


# ---------------------------------------------------------------- the file

def test_an_extract_reads_back_as_what_it_was_built_from():
    data = dump(ROWS, "debian", "12", only_fixable=False, source_modified=TRACKER_TIME)
    assert load(data) == (Header("debian", "12", False, TRACKER_TIME), ROWS)


def test_the_file_is_a_header_line_and_one_tab_separated_line_per_row():
    text = gzip.decompress(dump(ROWS, "debian", "12", only_fixable=False,
                                source_modified=TRACKER_TIME)).decode("ascii")
    assert text.splitlines() == [
        "whichports-cve-extract\t1\tdebian\t12\tall\t2026-10-03T14:07:28Z",
        "nginx\tCVE-2025-00030\t\tunimportant",
        "openssh\tCVE-2025-00001\t1:9.2p1-2+deb12u5\tlow",
        "openssh\tCVE-2025-00002\t\tnot yet assigned"]
    assert text.endswith("\n")


def test_the_same_rows_give_the_same_bytes_in_whatever_order_they_came():
    again = list(reversed(ROWS)) + [ROWS[0]]
    assert dump(ROWS, "debian", "12", only_fixable=False) == dump(
        again, "debian", "12", only_fixable=False)


def test_an_extract_is_built_only_for_a_release_this_code_knows():
    for distribution, version_id in (("debian", "11"), ("ubuntu", "22.04"), ("fedora", "44"),
                                     ("debian", "24.04")):
        with pytest.raises(ExtractError):
            dump([], distribution, version_id)


def test_the_time_of_the_vendors_file_is_a_time_or_nothing():
    assert load(dump([], "ubuntu", "24.04"))[0].source_modified == ""
    for bad in ("yesterday", "2026-10-03", "2026-10-03T14:07:28+02:00", "2026-10-03T14:07:28Z\n"):
        with pytest.raises(ExtractError):
            dump([], "ubuntu", "24.04", source_modified=bad)


@pytest.mark.parametrize("row", [
    Row("openssh", "CVE-2025-00001", "1:9.6p1-3ubuntu13.5", "not yet assigned"),  # Debian's word
    Row("openssh", "DSA-5868-1", "1:9.6p1-3ubuntu13.5", "medium"),
    Row("OpenSSH", "CVE-2025-00001", "1:9.6p1-3ubuntu13.5", "medium"),
    Row("openssh", "CVE-2025-00001", "1:9.6p1-", "medium"),
])
def test_a_row_that_is_not_one_of_that_release_is_not_written(row):
    with pytest.raises(ExtractError):
        dump([row], "ubuntu", "24.04")


def packed(text):
    return gzip.compress(text.encode("utf-8"), 9, mtime=0)


HEAD = "whichports-cve-extract\t1\tdebian\t12\tall\t\n"
GOOD = "openssh\tCVE-2025-00001\t1:9.2p1-2+deb12u5\tlow\n"


def test_an_extract_says_when_it_was_built_and_one_that_does_not_is_as_it_was():
    built = "2026-10-12T04:41:00Z"
    data = dump(ROWS, "debian", "12", only_fixable=False, source_modified=TRACKER_TIME, built=built)
    assert load(data) == (Header("debian", "12", False, TRACKER_TIME, built), ROWS)
    assert gzip.decompress(data).decode("ascii").split("\n")[0].split("\t")[-2:] == [TRACKER_TIME, built]
    # Without it the header is the six fields it always was, byte for byte.
    plain = dump(ROWS, "debian", "12", only_fixable=False, source_modified=TRACKER_TIME)
    assert len(gzip.decompress(plain).decode("ascii").split("\n")[0].split("\t")) == 6
    assert load(plain)[0].built == ""
    for bad in ("yesterday", "2026-10-12", "2026-10-12T04:41:00+00:00"):
        with pytest.raises(ExtractError):
            dump(ROWS, "debian", "12", built=bad)
        with pytest.raises(ExtractError, match="the time it was built is not a time"):
            load(packed(HEAD.rstrip("\n") + "\t" + bad + "\n"))
    # And a header of eight fields is no extract.
    with pytest.raises(ExtractError, match="not an extract"):
        load(packed(HEAD.rstrip("\n") + "\t" + built + "\t" + built + "\n"))


def test_the_smallest_extract_is_a_header_alone():
    assert load(packed(HEAD)) == (Header("debian", "12", False, ""), [])
    assert load(packed(HEAD + GOOD))[1] == [ROWS[1]]


@pytest.mark.parametrize("data", [
    b"",
    b"not gzip at all",
    packed(HEAD + GOOD)[:-9],                                             # cut short
    packed(""),
    packed("something-else\t1\tdebian\t12\tall\t\n"),
    packed("whichports-cve-extract\t2\tdebian\t12\tall\t\n"),             # a later format
    packed("whichports-cve-extract\t1\tdebian\t11\tall\t\n"),
    packed("whichports-cve-extract\t1\tfedora\t44\tall\t\n"),
    packed("whichports-cve-extract\t1\tdebian\t12\tsome\t\n"),
    packed("whichports-cve-extract\t1\tdebian\t12\tall\tyesterday\n"),
    packed("whichports-cve-extract\t1\tdebian\t12\tall\n"),               # a field short
    packed(HEAD + "openssh\tCVE-2025-00001\t1:9.2p1-2+deb12u5\n"),
    packed(HEAD + "openssh\tCVE-2025-00001\t1:9.2p1-2+deb12u5\tlow\textra\n"),
    packed(HEAD + "openssh\tDSA-5868-1\t1:9.2p1-2+deb12u5\tlow\n"),
    packed(HEAD + "openssh\tCVE-2025-00001\t1:9.2p1-\tlow\n"),
    packed(HEAD + "openssh\tCVE-2025-00001\t1:9.2p1-2+deb12u5\tsevere\n"),
    packed(HEAD + "OpenSSH\tCVE-2025-00001\t1:9.2p1-2+deb12u5\tlow\n"),
    packed(HEAD + GOOD + GOOD),                                           # one row twice
    packed(HEAD + GOOD + "nginx\tCVE-2025-00030\t\tunimportant\n"),      # not sorted
    packed(HEAD + GOOD + "\n"),                                           # an empty line
    packed((HEAD + GOOD)[:-1]),                                           # the last line cut
    packed(HEAD + "openssh\tCVE-2025-00001\t1:9.2p1-2+deb12u5\tlöw\n"),
    packed("whichports-cve-extract\t1\tdebian\t12\tfixable\t\n"
           "openssh\tCVE-2025-00002\t\tnot yet assigned\n"),              # unfixed in a fixable file
])
def test_a_file_that_is_not_a_whole_extract_is_refused_whole(data):
    """Half an extract read as all of it is a confident wrong answer."""
    with pytest.raises(ExtractError):
        load(data)


def test_an_extract_larger_than_one_is_refused(monkeypatch):
    data = packed(HEAD + GOOD)
    monkeypatch.setattr(cveextract, "MAX_EXTRACT_BYTES", 40)
    with pytest.raises(ExtractError):
        load(data)


# ------------------------------------------------------------- the command

def inputs(tmp_path, zipped=True):
    data = tracker({"CVE-2025-00001": entry(urgency="low"),
                    "CVE-2025-00002": entry("open", fixed=None),
                    "TEMP-0000001-ABCDEF": entry()})
    raw = json.dumps(data).encode()
    debian = tmp_path / ("tracker.json.gz" if zipped else "tracker.json")
    debian.write_bytes(gzip.compress(raw) if zipped else raw)
    ubuntu = tarball(tmp_path, [
        ("osv/cve/2025/UBUNTU-CVE-2025-00001.json", record()),
        ("osv/cve/2025/UBUNTU-CVE-2025-00002.json",
         record("UBUNTU-CVE-2025-00002", upstream=("CVE-2025-00002",),
                entries=[affected(fixed=None)])),
    ])
    return debian, ubuntu


def test_the_command_writes_one_extract_per_release_and_says_what_it_left_out(tmp_path, capsys):
    debian, ubuntu = inputs(tmp_path)
    out = tmp_path / "extracts"
    code = cveextract_cli.main(["--out", str(out), "--debian-tracker", str(debian),
                                "--debian-modified", TRACKER_TIME, "--ubuntu-osv", str(ubuntu)])
    assert code == cveextract_cli.EXIT_OK
    assert sorted(p.name for p in out.iterdir()) == [
        "debian-12.tsv.gz", "debian-13.tsv.gz", "ubuntu-24.04.tsv.gz", "ubuntu-26.04.tsv.gz"]
    header, rows = load((out / "debian-12.tsv.gz").read_bytes())
    assert header == Header("debian", "12", True, TRACKER_TIME)
    assert rows == [Row("openssh", "CVE-2025-00001", "1:9.2p1-2+deb12u5", "low")]
    assert load((out / "ubuntu-24.04.tsv.gz").read_bytes())[1] == [
        Row("openssh", "CVE-2025-00001", "1:9.6p1-3ubuntu13.5", "medium")]
    assert load((out / "ubuntu-26.04.tsv.gz").read_bytes())[1] == []
    said = capsys.readouterr().out.splitlines()
    assert said[0].startswith("debian 12: 1 rows, ")
    assert said[0].endswith("left out: 1 not a CVE id")
    assert said[1].startswith("debian 13: 0 rows, ")
    assert said[2].startswith("ubuntu 24.04: 1 rows, ") and "left out" not in said[2]


def test_keep_unfixed_turns_the_switch_the_other_way(tmp_path):
    debian, _ubuntu = inputs(tmp_path, zipped=False)
    out = tmp_path / "extracts"
    assert cveextract_cli.main(["--out", str(out), "--debian-tracker", str(debian),
                                "--keep-unfixed"]) == cveextract_cli.EXIT_OK
    assert sorted(p.name for p in out.iterdir()) == ["debian-12.tsv.gz", "debian-13.tsv.gz"]
    header, rows = load((out / "debian-12.tsv.gz").read_bytes())
    assert header.only_fixable is False
    assert [r.cve for r in rows] == ["CVE-2025-00001", "CVE-2025-00002"]


def test_the_command_needs_at_least_one_vendors_file(tmp_path):
    with pytest.raises(SystemExit) as stopped:
        cveextract_cli.main(["--out", str(tmp_path)])
    assert stopped.value.code == cveextract_cli.EXIT_USAGE


def test_a_file_that_cannot_be_read_stops_the_command_and_writes_nothing(tmp_path, capsys):
    broken = tmp_path / "tracker.json"
    broken.write_text("[1, 2, 3]")
    out = tmp_path / "extracts"
    assert cveextract_cli.main(["--out", str(out), "--debian-tracker", str(broken)]
                               ) == cveextract_cli.EXIT_REFUSED
    assert list(out.iterdir()) == []
    assert "not built" in capsys.readouterr().err
    missing = cveextract_cli.main(["--out", str(out), "--debian-tracker", str(tmp_path / "nope")])
    assert missing == cveextract_cli.EXIT_REFUSED


def test_no_half_written_file_is_left_beside_an_extract(tmp_path):
    debian, _ubuntu = inputs(tmp_path)
    out = tmp_path / "extracts"
    cveextract_cli.main(["--out", str(out), "--debian-tracker", str(debian)])
    assert not [p for p in out.iterdir() if p.name.endswith(".part")]
