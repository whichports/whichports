"""Bring the CVE extracts up to date. One command, run once a day.

    python -m app.cvesync_cli build --out DIR [--keep-unfixed]
    python -m app.cvesync_cli fetch --from URL
    python -m app.cvesync_cli daily

`build` fetches the two vendors' own files, Debian's security tracker JSON
and Canonical's OSV tarball, builds the extract of every release
(`app/cveextract.py`) and puts them in DIR. It is what our own box runs for
the files it serves, and what an instance runs when it will not ask us.

`fetch` downloads from URL the extract of each release this instance's
servers run, and no other, and puts them in the store (`app/cvestore.py`).

`daily` is the instance's job. It reads one setting, WHICHPORTS_CVE_DATA:
`whichports` fetches the extracts from WHICHPORTS_CVE_URL, `vendors` builds
them from the vendors' files, and unset does nothing and says so.

Reading Canonical's tarball takes minutes, so this is a job of its own on a
daily timer and never part of the five-minute sweep. Every request it makes
is in `app/cvefetch.py`, with what a fetch refuses. Nothing is swapped in
that did not load whole: when a download fails or a file is damaged,
yesterday's extract stays where it is.
"""

import argparse
import datetime
import io
import json
import os
import pathlib
import sys
import urllib.parse

from . import cveextract, cvefetch, cvematch, cvestore, db, store

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2

DATA_ENV = "WHICHPORTS_CVE_DATA"
URL_ENV = "WHICHPORTS_CVE_URL"
FROM_US = "whichports"
FROM_VENDORS = "vendors"


def build(out: pathlib.Path, only_fixable: bool = cveextract.ONLY_FIXABLE,
          fetch=cvefetch.fetch, now=None) -> list[str]:
    """Fetch both vendors' files, build every release's extract and put them
    in `out`. One line per release comes back. Every extract is built before
    the first is written, so a failure half way leaves `out` as it was.

    Each extract says when it was built, read once both downloads have
    succeeded. That is what a card holds against its three days
    (`cvecard.OLD_AFTER`): a vendor's file that did not change over a
    weekend is still this morning's data, and a job that failed since
    Thursday is not."""
    packed, tracker_time = fetch(cvefetch.DEBIAN_TRACKER_URL, cvefetch.VENDOR_HOSTS,
                                 cvefetch.MAX_TRACKER_BYTES,
                                 headers={"Accept-Encoding": "gzip"})
    tracker = json.loads(cvefetch.unpacked(packed, cvefetch.MAX_TRACKER_UNPACKED_BYTES))
    del packed
    tarball, tarball_time = fetch(cvefetch.UBUNTU_OSV_URL, cvefetch.VENDOR_HOSTS,
                                  cvefetch.MAX_TARBALL_DOWNLOAD_BYTES)
    fetched = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    built = []
    for version_id, codename in cveextract.DEBIAN_CODENAMES.items():
        rows, left_out = cveextract.debian_rows(tracker, codename)
        built.append(("debian", version_id, rows, left_out, tracker_time))
    del tracker
    found = cveextract.ubuntu_rows_for(cveextract.ubuntu_records(io.BytesIO(tarball)),
                                       cveextract.UBUNTU_ECOSYSTEMS.values())
    for version_id, ecosystem in cveextract.UBUNTU_ECOSYSTEMS.items():
        rows, left_out = found[ecosystem]
        built.append(("ubuntu", version_id, rows, left_out, tarball_time))
    files = []
    for distribution, version_id, rows, left_out, modified in built:
        data = cveextract.dump(rows, distribution, version_id, only_fixable=only_fixable,
                               source_modified=modified, built=fetched)
        kept = len(cveextract.select(rows, only_fixable))
        files.append((distribution, version_id, data, kept, left_out, modified))
    # Every extract is held against the one it would replace before the
    # first is written, so one that lost its rows leaves `out` as it was.
    for distribution, version_id, data, _kept, _left_out, _modified in files:
        cvestore.check(data, where=out, expect=(distribution, version_id))
    lines = []
    for distribution, version_id, data, kept, left_out, modified in files:
        cvestore.install(data, where=out, expect=(distribution, version_id))
        why = ", ".join(f"{count} {reason}" for reason, count in sorted(left_out.items()))
        lines.append(f"{distribution} {version_id}: {kept} rows, {len(data)} bytes,"
                     f" vendor's file of {modified or 'no stated time'}"
                     + (f", left out: {why}" if why else ""))
    return lines


def releases_in_use(con) -> list[tuple[str, str]]:
    """The releases this instance's servers run, read from the newest report
    of each server that is not removed. Only a release an extract exists for
    is in the answer."""
    found = set()
    for host in con.execute("SELECT id FROM hosts WHERE revoked_at IS NULL").fetchall():
        report = store.latest_report(con, host["id"])
        if report is None:
            continue
        try:
            document = json.loads(report["document"])
        except (TypeError, ValueError):
            continue
        section = document.get("packages") if isinstance(document, dict) else None
        if not isinstance(section, dict):
            continue
        release = cvematch.release_of(section.get("distribution"))
        if release is not None:
            found.add(release)
    return sorted(found)


def fetch_extracts(base_url: str, releases, where: pathlib.Path | None = None,
                   fetch=cvefetch.fetch) -> tuple[list[str], int]:
    """Download and put in place the extract of each release named. Returns
    one line per release and how many were not updated. A release that fails
    keeps the file it had."""
    host = urllib.parse.urlsplit(base_url).hostname or ""
    lines, failed = [], 0
    for distribution, version_id in releases:
        url = base_url.rstrip("/") + "/" + cvestore.file_name(distribution, version_id)
        try:
            data, _served = fetch(url, (host,), cvefetch.MAX_EXTRACT_DOWNLOAD_BYTES)
            header = cvestore.install(data, where=where, expect=(distribution, version_id))
        except (cvefetch.FetchError, cveextract.ExtractError) as exc:
            failed += 1
            lines.append(f"{distribution} {version_id}: not updated, {exc}")
            continue
        lines.append(f"{distribution} {version_id}: updated, vendor's file of"
                     f" {header.source_modified or 'no stated time'}")
    return lines, failed


def run(args, env=None, fetch=cvefetch.fetch) -> int:
    env = os.environ if env is None else env
    if args.command == "build":
        only_fixable = cveextract.ONLY_FIXABLE and not args.keep_unfixed
        for line in build(pathlib.Path(args.out), only_fixable, fetch):
            print(line)
        return EXIT_OK
    mode = env.get(DATA_ENV, "").strip() if args.command == "daily" else FROM_US
    if args.command == "daily" and mode == FROM_VENDORS:
        for line in build(cvestore.directory(env), cveextract.ONLY_FIXABLE, fetch):
            print(line)
        return EXIT_OK
    if args.command == "daily" and mode != FROM_US:
        print(f"{DATA_ENV} is not set to {FROM_US} or {FROM_VENDORS}: nothing fetched")
        return EXIT_OK
    base_url = args.source if args.command == "fetch" else env.get(URL_ENV, "").strip()
    if not base_url:
        print(f"{URL_ENV} is not set: nothing fetched", file=sys.stderr)
        return EXIT_FAILED
    con = db.connect()
    try:
        db.init(con)
        releases = releases_in_use(con)
    finally:
        con.close()
    if not releases:
        print("no server here runs a release an extract exists for: nothing fetched")
        return EXIT_OK
    lines, failed = fetch_extracts(base_url, releases, cvestore.directory(env), fetch)
    for line in lines:
        print(line)
    return EXIT_FAILED if failed else EXIT_OK


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m app.cvesync_cli",
        description="Bring the CVE extracts up to date.")
    commands = parser.add_subparsers(dest="command", required=True)
    built = commands.add_parser("build", help="build every extract from the vendors' files")
    built.add_argument("--out", required=True, metavar="DIR")
    built.add_argument("--keep-unfixed", action="store_true",
                       help="also keep the CVEs no update fixes")
    fetched = commands.add_parser("fetch", help="download the extracts this instance needs")
    fetched.add_argument("--from", dest="source", required=True, metavar="URL")
    commands.add_parser("daily", help=f"what {DATA_ENV} says: {FROM_US}, {FROM_VENDORS} or nothing")
    return parser.parse_args(argv)


def main(argv=None, env=None, fetch=cvefetch.fetch) -> int:
    args = parse_args(argv)
    try:
        return run(args, env, fetch)
    except (cvefetch.FetchError, cveextract.ExtractError, OSError, ValueError) as exc:
        print(f"not updated: {exc}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
