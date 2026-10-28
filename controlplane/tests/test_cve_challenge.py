"""The challenge to the CVE check, 2026-10-11. Each test here fails on
`cve-control-plane` at bfc81fd, and each is one input for which a customer's
screen would say something the distribution's own data does not.

    python -m pytest tests/test_cve_challenge.py

Every version below was read on 2026-10-11 from the archive or the vendor's
file named beside it. Nothing here is fixed. The tests say what should hold.
"""
import gzip
import io
import json
import tarfile
from datetime import datetime, timezone

from app import cvecard, cveextract, cvematch, cvestore, cvesync_cli, offerrule
from app.cveextract import Row
from app.offerrule import NOT_THE_DISTRIBUTIONS, Checked, NotChecked, held
from app.packagerule import Named

DEBIAN = {"id": "debian", "version_id": "12", "version_codename": "bookworm"}
UBUNTU = {"id": "ubuntu", "version_id": "24.04", "version_codename": "noble"}


def offer(version, archive="debian", flagged=False):
    return {"version": version, "archive": archive,
            "not_automatic": flagged, "but_automatic_upgrades": flagged}


def offers(name, *offered, other=False, other_installed=False):
    return {"name": name, "offered": list(offered),
            "other_offers": other, "other_offers_installed": other_installed}


def doc(*entries, distribution=DEBIAN):
    return {"packages": {"status": "collected", "distribution": distribution,
                         "sources": {"apt_lists": {"status": "collected"}},
                         "offers": list(entries)}}


# ------------------------------------------- another archive's build, behind

def test_another_archives_build_behind_on_its_own_updates_is_not_drawn_as_the_distributions():
    """MariaDB's own 10.11 on Debian 12, installed a while ago and not
    updated since.

    MariaDB's archive lists only its two newest, `1:10.11.19+maria~deb12` and
    `1:10.11.18+maria~deb12` (mirror.mariadb.org/repo/10.11/debian, bookworm,
    Packages, read 2026-10-11). So the installed `1:10.11.11+maria~deb12` is
    in no list: another archive offers the package, and not this version.
    Debian's own bookworm offers `1:10.11.18-0+deb12u1` (deb.debian.org,
    bookworm main Packages, the same day), which sorts above the installed
    one. All four conditions of the spec's 8.1 point 2 hold, and the card
    reads `update fixes`, `update to 1:10.11.18-0+deb12u1`, for a build that
    is MariaDB's and that apt would move to MariaDB's 10.11.19.

    The spec's own third case says this package reads `not the
    distribution's package`. It does so only while its version stands above
    all that Debian offers."""
    mariadb = Named("mariadb-server", "1:10.11.11+maria~deb12", "mariadb", "1:10.11.11+maria~deb12", "amd64")
    # Debian's tracker, bookworm, read 2026-10-11: mariadb fixed in these two
    # after 10.11.11. The CVE numbers are made up.
    index = cvematch.by_source([Row("mariadb", "CVE-2026-00001", "1:10.11.13-0+deb12u1", "low"),
                                Row("mariadb", "CVE-2026-00002", "1:10.11.18-0+deb12u1", "low")])
    lists = doc(offers("mariadb-server", offer("1:10.11.18-0+deb12u1"), other=True, other_installed=False))
    got = held(lists, mariadb, index)
    assert isinstance(got, NotChecked), f"drawn as Debian's own: {got}"


# ------------------------------------------------- `none` on a server with Pro

def _pro_only_record():
    """Canonical's own record UBUNTU-CVE-2023-40184, cut to its entry for
    24.04, as it stands in osv-all.tar.xz of 2026-10-09 18:41 UTC, read
    2026-10-11: xrdp is named under Pro's data set only, and there is no
    entry under `Ubuntu:24.04:LTS` at all."""
    return {"id": "UBUNTU-CVE-2023-40184", "upstream": ["CVE-2023-40184"],
            "severity": [{"type": "Ubuntu", "score": "medium"}],
            "affected": [{"package": {"ecosystem": "Ubuntu:Pro:24.04:LTS", "name": "xrdp"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "0.9.24-4ubuntu0.1~esm1"}]}],
                          "versions": ["0.9.24-4"]}]}


def test_none_is_not_said_where_another_archive_in_the_lists_offers_the_package():
    """An Ubuntu 24.04 server with Ubuntu Pro, xrdp `0.9.24-4` as the release
    shipped it. Pro's archive is in the server's lists and says of itself
    `Origin: UbuntuESMApps`, `Label: UbuntuESMApps`
    (esm.ubuntu.com/apps/ubuntu/dists/noble-apps-security/InRelease, read
    2026-10-11), so the agent's closed list makes it another archive and
    sends `other_offers: true`. It offers `0.9.24-4ubuntu0.1~esm1`, which
    Canonical's own record says fixes this CVE.

    The card reads `update fixes none`. On this server an update in its own
    package lists fixes a CVE, and the rule holds the fact that another
    archive offers the package and does not look at it."""
    rows, _left_out = cveextract.ubuntu_rows_for([_pro_only_record()], ["Ubuntu:24.04:LTS"])["Ubuntu:24.04:LTS"]
    index = cvematch.by_source(cveextract.select(rows))
    xrdp = Named("xrdp", "0.9.24-4", "xrdp", "0.9.24-4", "amd64")
    lists = doc(offers("xrdp", offer("0.9.24-4", "ubuntu"), other=True, other_installed=False),
                distribution=UBUNTU)
    got = held(lists, xrdp, index)
    assert not (isinstance(got, Checked) and got.none), "reads `none` beside an archive that offers a newer build"


# ---------------------------------- the words for a build of the distribution's

def test_the_distributions_own_security_build_is_not_said_to_be_somebody_elses():
    """Debian's own redis-server `5:7.0.15-1~deb12u10`, which stands in
    bookworm-security (security.debian.org, Packages, read 2026-10-11), on a
    server whose lists hold bookworm main alone, where it is `~deb12u7`
    (deb.debian.org, the same day). No other archive offers the package.

    What was read: the installed version stands above what this server's
    lists offer from the distribution. The card says `not the distribution's
    package`, which is a cause, and here a wrong one. The rule's own words
    for the case beside it are "whose it is was not read"."""
    redis = Named("redis-server", "5:7.0.15-1~deb12u10", "redis", "5:7.0.15-1~deb12u10", "amd64")
    lists = doc(offers("redis-server", offer("5:7.0.15-1~deb12u7"), other=False, other_installed=False))
    got = held(lists, redis, cvematch.by_source([]))
    assert isinstance(got, NotChecked)
    assert got.reason != NOT_THE_DISTRIBUTIONS, "Debian's own build is called not the distribution's"


# ----------------------------------------- a vendor's file that holds nothing

def _tarball(records):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:xz") as archive:
        for number, record in enumerate(records):
            data = json.dumps(record).encode()
            info = tarfile.TarInfo(f"osv/cve/2026/{number}.json")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue()


def _vendors(tracker):
    def fetch(url, allowed_hosts, max_bytes, headers=None):
        if "debian" in url:
            return gzip.compress(json.dumps(tracker).encode()), "2026-10-11T13:23:56Z"
        return _tarball([]), "2026-10-09T18:41:58Z"
    return fetch


def test_a_vendor_file_that_holds_nothing_does_not_replace_yesterdays_extract(tmp_path):
    """The tracker answers 200 with `{}` one morning: valid JSON, a fresh
    Last-Modified, no source package in it. The spec's rule 9 and its answer
    to objection 10 say an extract that lost a quarter of yesterday's rows
    is refused and yesterday's stays. Nothing holds that. The empty extract
    is put in place, it is a day old at most, and every Debian 12 port that
    carried CVEs yesterday reads `update fixes none`."""
    tracker = {"openssh": {"CVE-2026-00001": {"releases": {"bookworm": {
        "status": "resolved", "fixed_version": "1:9.2p1-2+deb12u10", "urgency": "low",
        "repositories": {"bookworm": "1:9.2p1-2+deb12u10"}}}}}}
    cvesync_cli.build(tmp_path, fetch=_vendors(tracker))
    assert len(cvestore.read("debian", "12", tmp_path).by_source["openssh"]) == 1
    try:
        cvesync_cli.build(tmp_path, fetch=_vendors({}))
    except (cveextract.ExtractError, ValueError):
        pass
    kept = cvestore.read("debian", "12", tmp_path)
    assert kept.by_source.get("openssh"), "yesterday's rows are gone and the port now reads none"


def test_a_port_reads_none_from_an_extract_with_no_rows_at_all():
    """The same hole at the card: an extract of today with no row in it is
    believed, and a package three updates behind reads `none`."""
    ssh = {"unit": "ssh.service", "finding": "complete", "program_kind": "elf",
           "unit_file": {"path": "/usr/lib/systemd/system/ssh.service", "owners": [
               {"name": "openssh-server", "installed": True, "version": "1:9.2p1-2+deb12u3", "source": "openssh"}]},
           "program": {"path": "/usr/sbin/sshd", "owners": [
               {"name": "openssh-server", "installed": True, "version": "1:9.2p1-2+deb12u3", "source": "openssh"}]}}
    report = {"sockets": {"listening": [{"protocol": "tcp", "family": "v4", "port": 22,
                                         "cgroup": "/system.slice/ssh.service", "unit": "ssh.service"}]},
              "packages": {"status": "collected", "distribution": DEBIAN,
                           "sources": {"dpkg_info": {"status": "collected"}, "apt_lists": {"status": "collected"}},
                           "units": [ssh], "offers": [offers("openssh-server", offer("1:9.2p1-2+deb12u10"))]}}
    header, rows = cveextract.load(cveextract.dump([], "debian", "12", source_modified="2026-10-11T13:23:56Z"))
    empty = cvestore.Stored(header, cvematch.by_source(rows))
    now = datetime(2026, 10, 11, 14, 0, tzinfo=timezone.utc)
    card = cvecard.card_for(report, "tcp", "v4", 22, lambda *release: empty, now)
    said = [(line.label, line.value) for line in card.lines]
    assert (cvecard.UPDATE_FIXES, cvecard.NONE) not in said, "an extract with no rows makes every port read none"


# ------------------------------------------------------ a download cut short

def test_a_download_cut_short_is_a_refusal_and_not_a_traceback():
    """The host says how long the file is and the connection ends before
    that. urllib raises `http.client.IncompleteRead`, which is none of the
    three classes `cvefetch.fetch` turns into a refusal and none of the four
    `cvesync_cli.main` catches. Nothing is put in place, which is right.
    But the job ends in a traceback, and in `fetch_extracts` the releases
    after the one that was cut are not asked for that day, where the module
    says a release that fails keeps its file and the others still update."""
    import http.client

    from app import cvefetch

    class Cut:
        status = 200
        headers = {}

        def read(self, amount):
            raise http.client.IncompleteRead(b"x" * 10, 90)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class Opener:
        def open(self, request, timeout):
            return Cut()

    try:
        cvefetch.fetch(cvefetch.DEBIAN_TRACKER_URL, cvefetch.VENDOR_HOSTS, 100,
                       resolver=lambda host: ["185.199.108.153"], opener=Opener())
    except cvefetch.FetchError:
        return
    except Exception as exc:
        raise AssertionError(f"not a refusal: {type(exc).__name__}") from None
    raise AssertionError("a cut download was believed")
