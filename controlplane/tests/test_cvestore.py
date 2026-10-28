"""Where the CVE extracts are kept, and that a reader never meets half a file.

    python -m pytest tests/test_cvestore.py
"""
import pytest

from app import cveextract, cvestore, db
from app.cveextract import ExtractError, Header, Row

ROWS = [Row("openssh", "CVE-2025-00001", "1:9.2p1-2+deb12u5", "low")]
TIME = "2026-10-03T14:07:28Z"


def extract(rows=ROWS, distribution="debian", version_id="12", modified=TIME):
    return cveextract.dump(rows, distribution, version_id, source_modified=modified)


def test_the_extracts_are_kept_beside_the_database_unless_told_otherwise(tmp_path):
    assert cvestore.directory({db.DB_ENV: str(tmp_path / "data" / "whichports.db")}) == (
        tmp_path / "data" / "cve").resolve()
    assert cvestore.directory({cvestore.DIR_ENV: str(tmp_path / "elsewhere"),
                               db.DB_ENV: str(tmp_path / "whichports.db")}) == tmp_path / "elsewhere"


def test_a_release_has_a_file_name_or_no_extract_is_kept_for_it():
    assert cvestore.file_name("debian", "12") == "debian-12.tsv.gz"
    assert cvestore.file_name("ubuntu", "24.04") == "ubuntu-24.04.tsv.gz"
    for distribution, version_id in (("debian", "11"), ("fedora", "44"), ("../etc", "passwd"),
                                     ("debian", "12/../../x")):
        with pytest.raises(ExtractError):
            cvestore.file_name(distribution, version_id)


def test_an_installed_extract_is_the_file_and_nothing_is_left_beside_it(tmp_path):
    header = cvestore.install(extract(), where=tmp_path / "cve")
    assert header == Header("debian", "12", True, TIME)
    assert [p.name for p in (tmp_path / "cve").iterdir()] == ["debian-12.tsv.gz"]
    assert (tmp_path / "cve" / "debian-12.tsv.gz").read_bytes() == extract()


@pytest.mark.parametrize("data", [b"", b"not an extract", extract()[:-9]])
def test_bytes_that_are_not_a_whole_extract_are_not_swapped_in(tmp_path, data):
    """Yesterday's file stays exactly as it was."""
    cvestore.install(extract(), where=tmp_path)
    before = (tmp_path / "debian-12.tsv.gz").read_bytes()
    with pytest.raises(ExtractError):
        cvestore.install(data, where=tmp_path)
    assert (tmp_path / "debian-12.tsv.gz").read_bytes() == before
    assert [p.name for p in tmp_path.iterdir()] == ["debian-12.tsv.gz"]


def test_an_extract_of_another_release_than_asked_for_is_refused(tmp_path):
    with pytest.raises(ExtractError):
        cvestore.install(extract(), where=tmp_path, expect=("debian", "13"))
    assert list(tmp_path.iterdir()) == []
    assert cvestore.install(extract(), where=tmp_path, expect=("debian", "12")).version_id == "12"


def test_reading_a_release_with_no_file_is_none(tmp_path):
    assert cvestore.read("debian", "12", where=tmp_path) is None


def test_reading_gives_the_header_and_the_rows_under_their_source_package(tmp_path):
    cvestore.install(extract(), where=tmp_path)
    stored = cvestore.read("debian", "12", where=tmp_path)
    assert stored.header == Header("debian", "12", True, TIME)
    assert stored.by_source == {"openssh": (ROWS[0],)}


def test_a_swap_is_seen_at_the_next_read_and_no_old_copy_is_handed_out(tmp_path):
    cvestore.install(extract(), where=tmp_path)
    first = cvestore.read("debian", "12", where=tmp_path)
    assert cvestore.read("debian", "12", where=tmp_path) is first, "read again with no swap"
    newer = [Row("nginx", "CVE-2025-00030", "1.22.1-9+deb12u2", "medium")]
    cvestore.install(extract(newer, modified="2026-10-04T14:07:28Z"), where=tmp_path)
    second = cvestore.read("debian", "12", where=tmp_path)
    assert second.header.source_modified == "2026-10-04T14:07:28Z"
    assert set(second.by_source) == {"nginx"}


def test_a_file_that_was_taken_away_reads_as_none_again(tmp_path):
    cvestore.install(extract(), where=tmp_path)
    assert cvestore.read("debian", "12", where=tmp_path) is not None
    (tmp_path / "debian-12.tsv.gz").unlink()
    assert cvestore.read("debian", "12", where=tmp_path) is None


def test_a_damaged_file_put_there_by_hand_is_refused_and_not_read_as_empty(tmp_path):
    (tmp_path / "debian-12.tsv.gz").write_bytes(b"half a file")
    with pytest.raises(ExtractError):
        cvestore.read("debian", "12", where=tmp_path)


# ------------------------------------- an extract that lost its rows

def _extract(count, modified="2026-10-11T13:23:56Z"):
    rows = [cveextract.Row("openssh", f"CVE-2026-{n:05d}", "1:9.2p1-2+deb12u10", "low") for n in range(count)]
    return cveextract.dump(rows, "debian", "12", source_modified=modified)


def test_an_extract_that_lost_a_quarter_of_its_rows_is_refused_and_yesterdays_stays(tmp_path):
    """A vendor's file that answers whole and holds half of what it held is
    a fault of that morning. Put in place it would be believed, and every
    port that lost its rows would read none. So it is refused, yesterday's
    stays, and yesterday's is said as old once it is (app/cvecard.py)."""
    cvestore.install(_extract(100), tmp_path)
    for fewer in (74, 50, 1, 0):
        with pytest.raises(cveextract.ExtractError):
            cvestore.install(_extract(fewer), tmp_path)
        assert len(cvestore.read("debian", "12", tmp_path).by_source["openssh"]) == 100
    assert not list(tmp_path.glob("*.part")), "a refused extract left a file behind"


def test_an_extract_that_kept_three_quarters_of_its_rows_replaces_yesterdays(tmp_path):
    """A vendor does withdraw records. Three quarters is where a morning's
    fault is told from a day's change, and an extract that grew is always
    taken."""
    cvestore.install(_extract(100), tmp_path)
    cvestore.install(_extract(75), tmp_path)
    assert len(cvestore.read("debian", "12", tmp_path).by_source["openssh"]) == 75
    cvestore.install(_extract(400), tmp_path)
    assert len(cvestore.read("debian", "12", tmp_path).by_source["openssh"]) == 400


def test_with_nothing_kept_or_a_kept_file_that_is_no_extract_there_is_nothing_to_lose(tmp_path):
    cvestore.install(_extract(3), tmp_path)
    (tmp_path / "debian-12.tsv.gz").write_bytes(b"not an extract")
    cvestore.install(_extract(1), tmp_path)
    assert len(cvestore.read("debian", "12", tmp_path).by_source["openssh"]) == 1


def test_a_check_writes_nothing(tmp_path):
    cvestore.check(_extract(5), tmp_path, expect=("debian", "12"))
    assert list(tmp_path.iterdir()) == []
