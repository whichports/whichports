"""Build the slim CVE extracts from the vendors' own files.

    python -m app.cveextract_cli --out DIR \\
        --debian-tracker tracker.json.gz --debian-modified 2026-10-03T14:07:28Z \\
        --ubuntu-osv osv-all.tar.xz --ubuntu-modified 2026-10-02T18:10:09Z

writes one file per release into DIR, `debian-12.tsv.gz` and so on, and
prints for each how many rows it holds and what was left out and why.
`app/cveextract.py` owns what a row is and which releases there are.

It reads files it is given and writes files. It fetches nothing: where the
vendors' files come from, and the request that brings an extract to an
instance, are named on the page the day they ship (`docs/RECORD.md` 4.274).

`--keep-unfixed` turns the one switch the other way and keeps the CVEs no
update fixes. Without it the extracts hold only what an update fixes, which
is the answer of 2026-10-03 (4.285).

Either input may be left out, and then that distribution's extracts are not
written. A file is written beside its final name and moved into place, so a
reader never finds half of one.
"""

import argparse
import gzip
import json
import os
import pathlib
import sys

from . import cveextract

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2


def read_tracker(path: pathlib.Path):
    """Debian's tracker JSON, parsed. The file as the tracker serves it with
    gzip, or the same unpacked, told apart by its first two bytes."""
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return json.loads(raw)


def write_in_place(path: pathlib.Path, data: bytes) -> None:
    """The whole file or none of it: written beside its name, then moved."""
    beside = path.with_name(path.name + ".part")
    beside.write_bytes(data)
    os.replace(beside, path)


def report_line(distribution, version_id, kept, data, left_out) -> str:
    why = ", ".join(f"{count} {reason}" for reason, count in sorted(left_out.items()))
    return (f"{distribution} {version_id}: {len(kept)} rows, {len(data)} bytes"
            + (f", left out: {why}" if why else ""))


def run(args) -> int:
    only_fixable = cveextract.ONLY_FIXABLE and not args.keep_unfixed
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    built = []
    if args.debian_tracker:
        tracker = read_tracker(pathlib.Path(args.debian_tracker))
        for version_id, codename in cveextract.DEBIAN_CODENAMES.items():
            rows, left_out = cveextract.debian_rows(tracker, codename)
            built.append(("debian", version_id, rows, left_out, args.debian_modified))
    if args.ubuntu_osv:
        # One pass for every release: the records are 11 GB unpacked and are
        # read one at a time, never kept.
        found = cveextract.ubuntu_rows_for(cveextract.ubuntu_records(args.ubuntu_osv),
                                           cveextract.UBUNTU_ECOSYSTEMS.values())
        for version_id, ecosystem in cveextract.UBUNTU_ECOSYSTEMS.items():
            rows, left_out = found[ecosystem]
            built.append(("ubuntu", version_id, rows, left_out, args.ubuntu_modified))
    for distribution, version_id, rows, left_out, modified in built:
        kept = cveextract.select(rows, only_fixable)
        data = cveextract.dump(rows, distribution, version_id, only_fixable=only_fixable,
                               source_modified=modified)
        write_in_place(out / f"{distribution}-{version_id}.tsv.gz", data)
        print(report_line(distribution, version_id, kept, data, left_out))
    return EXIT_OK


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m app.cveextract_cli",
        description="Build the slim CVE extracts from the vendors' own files.")
    parser.add_argument("--out", required=True, metavar="DIR",
                        help="where the extracts are written")
    parser.add_argument("--debian-tracker", metavar="FILE",
                        help="Debian's security tracker JSON, gzipped or not")
    parser.add_argument("--debian-modified", metavar="TIME", default="",
                        help="when that file last changed, like 2026-10-03T14:07:28Z")
    parser.add_argument("--ubuntu-osv", metavar="FILE",
                        help="Canonical's osv-all.tar.xz")
    parser.add_argument("--ubuntu-modified", metavar="TIME", default="",
                        help="when that file last changed")
    parser.add_argument("--keep-unfixed", action="store_true",
                        help="also keep the CVEs no update fixes")
    args = parser.parse_args(argv)
    if not args.debian_tracker and not args.ubuntu_osv:
        parser.error("give --debian-tracker, --ubuntu-osv, or both")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        return run(args)
    except (cveextract.ExtractError, OSError, ValueError) as exc:
        print(f"not built: {exc}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
