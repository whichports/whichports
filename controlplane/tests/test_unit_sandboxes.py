"""Every unit that locks the file system down keeps a temporary directory.

    Run from controlplane: .venv/bin/python -m pytest tests/test_unit_sandboxes.py

ProtectSystem=strict mounts the whole file system read-only, /tmp and
/var/tmp included, and PrivateTmp=yes is what gives them back (systemd.exec:
"if ProtectSystem= is set to strict and PrivateTmp= is enabled, then /tmp/
and /var/tmp/ will be writable"). SQLite needs one the moment a sort no
longer fits its page cache, and from 2026-08-29 to 2026-09-15 the ingest,
the one unit without the line, failed every dashboard join with "disk I/O
error" while the sweep and the probes, which carry it, kept working
(docs/RECORD.md 4.183). This is the test that fails the way production
failed: it read the unit files, and the ingest's lacked the line.
"""

import pathlib

import pytest

OPS = pathlib.Path(__file__).resolve().parents[1] / "ops"
UNITS = sorted(OPS.glob("*.service"))


def service_section(text):
    """{key: value} of the [Service] section, comments dropped. The last
    assignment of a key wins, the way systemd reads it."""
    out = {}
    inside = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            inside = stripped == "[Service]"
            continue
        if not inside or not stripped or stripped.startswith("#"):
            continue
        key, _sep, value = stripped.partition("=")
        out[key.strip()] = value.strip()
    return out


def test_the_units_are_there_to_read():
    names = {u.name for u in UNITS}
    assert {"whichports-ingest.service", "whichports-sweep.service",
            "whichports-probe.service", "whichports-probe-fast.service",
            "whichports-scan.service", "whichports-backup.service"} <= names


@pytest.mark.parametrize("unit", UNITS, ids=[u.name for u in UNITS])
def test_a_strict_unit_keeps_a_writable_temporary_directory(unit):
    service = service_section(unit.read_text())
    if service.get("ProtectSystem") != "strict":
        return
    assert service.get("PrivateTmp") == "yes", (
        f"{unit.name} sets ProtectSystem=strict without PrivateTmp=yes, so /tmp"
        " and /var/tmp are read-only inside it and SQLite's first spilled sort"
        " fails with 'disk I/O error' (docs/RECORD.md 4.183)")


def test_the_ingest_is_the_unit_that_lacked_it():
    """Named on its own, because it is the one that renders the dashboard and
    the one that was missing the line for seventeen days."""
    service = service_section((OPS / "whichports-ingest.service").read_text())
    assert service["ProtectSystem"] == "strict"
    assert service["PrivateTmp"] == "yes"
    assert service["ReadWritePaths"] == "/var/lib/whichports-controlplane"
