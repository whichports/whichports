"""Where the CVE extracts are kept: one file per release, in a directory
beside the database.

A file and not a table, because an extract is a download: it arrives whole,
is checked whole, and replaces yesterday's whole. A self-hosted instance may
also put one there by hand, built with `app.cveextract_cli`.

**A reader never meets half a file.** `install` checks the bytes are a whole
extract of the release they claim, writes them beside their final name and
renames. A file that does not load is not swapped in, so yesterday's stays.

**The engine holds no copy that outlives a swap.** `read` keeps what it
parsed, keyed by the file's own identity, and reads again the moment the file
on disk is another one.
"""

import dataclasses
import os
import pathlib

from . import cveextract, cvematch, db

DIR_ENV = "WHICHPORTS_CVE_DIR"


def directory(env=None) -> pathlib.Path:
    """The directory the extracts are kept in: WHICHPORTS_CVE_DIR when it is
    set, or `cve` beside the database."""
    env = os.environ if env is None else env
    named = (env.get(DIR_ENV) or "").strip()
    if named:
        return pathlib.Path(named)
    return pathlib.Path(env.get(db.DB_ENV, db.DEFAULT_DB)).resolve().parent / "cve"


def file_name(distribution: str, version_id: str) -> str:
    """`debian-12.tsv.gz`, for a release an extract exists for."""
    if cvematch.release_of({"id": distribution, "version_id": version_id}) is None:
        raise cveextract.ExtractError(
            f"no extract is kept for {distribution!r} {version_id!r}")
    return f"{distribution}-{version_id}.tsv.gz"


# An extract with fewer rows than this share of the one it would replace is
# refused, and yesterday's stays. A vendor's file that answers whole and
# holds nothing, or half of what it held, is a fault of that morning and not
# the day every CVE was withdrawn, and an extract put in place is believed:
# every port that carried CVEs would read none. Yesterday's then grows old
# and is said as old after three days (`app/cvecard.py`).
LEAST_SHARE_OF_KEPT = 0.75


def check(data: bytes, where: pathlib.Path | None = None,
          expect: tuple[str, str] | None = None) -> cveextract.Header:
    """What an extract says about itself, or a refusal, with nothing
    written: the bytes are not a whole extract, are not the release `expect`
    names, or hold fewer rows than three quarters of the extract kept for
    that release."""
    header, rows = cveextract.load(data)
    if expect is not None and (header.distribution, header.version_id) != tuple(expect):
        raise cveextract.ExtractError(
            f"asked for {expect[0]} {expect[1]} and got"
            f" {header.distribution} {header.version_id}")
    where = directory() if where is None else pathlib.Path(where)
    final = where / file_name(header.distribution, header.version_id)
    try:
        _kept_header, kept_rows = cveextract.load(final.read_bytes())
    except (FileNotFoundError, cveextract.ExtractError):
        # Nothing kept, or a file there that is no extract: nothing to lose.
        kept_rows = []
    if len(rows) < len(kept_rows) * LEAST_SHARE_OF_KEPT:
        raise cveextract.ExtractError(
            f"{header.distribution} {header.version_id} holds {len(rows)} rows where the extract"
            f" kept holds {len(kept_rows)}, so the one kept stays")
    return header


def install(data: bytes, where: pathlib.Path | None = None,
            expect: tuple[str, str] | None = None) -> cveextract.Header:
    """Put one extract in place and return what it says about itself.
    Refused by `check`, with nothing written."""
    header = check(data, where, expect)
    where = directory() if where is None else pathlib.Path(where)
    where.mkdir(parents=True, exist_ok=True)
    final = where / file_name(header.distribution, header.version_id)
    beside = final.with_name(final.name + ".part")
    beside.write_bytes(data)
    os.replace(beside, final)
    return header


@dataclasses.dataclass(frozen=True)
class Stored:
    """One release's extract as the matcher reads it."""
    header: cveextract.Header
    by_source: dict


# What was parsed last, by path: the file's identity and the result. A swap
# gives the path another inode, so the identity differs and it is read again.
_parsed: dict = {}


def read(distribution: str, version_id: str,
         where: pathlib.Path | None = None) -> Stored | None:
    """The extract kept for a release, or None when none is kept. Raises
    `cveextract.ExtractError` when the file there is not a whole extract."""
    where = directory() if where is None else pathlib.Path(where)
    path = where / file_name(distribution, version_id)
    try:
        stat = path.stat()
    except FileNotFoundError:
        _parsed.pop(path, None)
        return None
    identity = (stat.st_ino, stat.st_mtime_ns, stat.st_size)
    kept = _parsed.get(path)
    if kept is not None and kept[0] == identity:
        return kept[1]
    header, rows = cveextract.load(path.read_bytes())
    stored = Stored(header, cvematch.by_source(rows))
    _parsed[path] = (identity, stored)
    return stored


def kept(distribution: str, version_id: str, where: pathlib.Path | None = None):
    """`read`, for a caller that must not stop on a file that is no extract:
    the page and the sweep. A file there that is not a whole extract is read
    as none kept, so a port says there is no data for its release."""
    try:
        return read(distribution, version_id, where)
    except cveextract.ExtractError:
        return None
