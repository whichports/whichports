"""Scan now: the host-page button and what its click does. The backend and
the decision are docs/PRODUCT.md 5f, the screen is
docs/screens/host-overview/SPEC.md. This covers what a person sees and clicks.

Its own file on purpose, the same reason test_screens.py is: parallel branches
that all grow test_render_live.py collide in it, so a screen that adds a control
adds its tests here instead.
"""
import json
import pathlib
import sqlite3
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402


ONESHOT = "sudo whichports-agent --mode=oneshot"


# ------------------------------------------------------------- the dialog

def test_there_is_no_scan_dialog_and_no_command_on_the_screen():
    """Until 2026-09-21 a window opened here, kept on 2026-09-06 to hold the
    one-shot command for the agent, with two sentences about which ports a
    scan covers. The owner, 2026-09-20, asked why a scan needed a command run by
    hand on a server. The agent reports by itself every fifteen
    minutes, so the command is nobody's step, and the spec had said "with no
    dialog" all along (docs/screens/host-overview/SPEC.md). What Scan now
    does instead is held in test_probing_mark.py."""
    assert not hasattr(build, "scan_modal")
    page = build.build_sample()
    assert 'id="scan-ovl"' not in page
    assert ONESHOT not in page
    assert "not a full sweep" not in page.lower()


# ------------------------------------------------------- the host-page button

def test_the_host_page_button_is_secondary_and_carries_the_host():
    """Host page only and secondary weight (the owner, 5f). It is js-scan, not the
    js-act stub it replaced, and it names its host so the click knows which
    one to probe. Read from the button a live page draws: until 2026-10-07
    this read the sample page, which drew the live button too
    (docs/RECORD.md 4.443)."""
    html = build.scan_button("host")
    assert html == '<button class="btn js-scan" data-host="host">Scan now</button>'
    # The old primary stub is gone, word and all.
    sample = build.sample_host_view()
    assert "Check now" not in sample
    assert "An on-demand check of this host" not in sample


def test_the_scan_button_is_not_primary_weight():
    """Secondary, so it does not compete with the primary action on a screen.
    Neither the live button nor the sample's carries the pri class."""
    for html in (build.scan_button("host"), build.sample_host_view()):
        assert ">Scan now<" in html
        button = html[html.rindex("<button", 0, html.index(">Scan now<")):html.index(">Scan now<")]
        assert "pri" not in button.split('class="', 1)[1].split('"', 1)[0].split()


def test_the_samples_scan_now_says_what_it_would_do():
    """Nothing is wired to a control plane on the sample page, so every
    control there says what it would do. Scan now was the one that posted:
    on a page served with nothing behind it the click answered "That did not
    work, HTTP 501" (the outside review of 2026-10-06, docs/RECORD.md 4.443)."""
    sample = build.sample_host_view()
    assert '<button class="btn js-act" data-msg="The server would be scanned here">Scan now</button>' in sample
    assert 'js-scan"' not in sample


def test_a_live_servers_page_keeps_the_button_that_scans(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", trl.document(listening=[trl.SSHD]))
    page = rl.render(path, now=trl.NOW)
    assert '<button class="btn js-scan" data-host="box">Scan now</button>' in page
    assert "The server would be scanned here" not in page


# ------------------------------------------------- the page wires them together

def test_the_page_carries_the_click_handler_and_the_fact_it_marks():
    """A button that shows nothing is a dead control. The assembled page holds
    the handler and the Probed fact the click marks."""
    page = build.build_sample()
    assert ".js-scan" in page
    assert "/scan" in page  # the endpoint the click posts to
    # and what the click shows is the Probed fact turning, which the sample
    # page carries too
    assert "data-probed=" in page and "classList.add('probing')" in page


def test_the_fleet_button_no_longer_claims_the_prober_is_unbuilt():
    """The fleet Check now used to toast that on-demand checks arrive with the
    prober, which is now a lie: the prober runs and Scan now is built, per host.
    The fleet button points at the host page instead."""
    page = build.build_sample()
    assert "arrive with the prober" not in page
    assert "would start here" not in page


# ---------------------------------------------------------- on a live page

# The minimal control-plane schema, copied rather than imported so this file
# stands alone (the same posture test_render_live.py takes and guards).
SCHEMA = """
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL, revoked_at TEXT, last_report_at TEXT,
    paused INTEGER NOT NULL DEFAULT 0, auto_named INTEGER NOT NULL DEFAULT 0);
CREATE TABLE reports (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
    received_at TEXT NOT NULL, collected_at_unix INTEGER NOT NULL,
    schema_version INTEGER NOT NULL, document TEXT NOT NULL);
"""

NOW = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)


def _minimal_document():
    return {
        "schema_version": 1,
        "hostname": "Almabox",
        "collected_at_unix": int(NOW.timestamp()),
        "sockets": {"status": "collected", "listening": []},
        "nftables": {"status": "not_present"},
        "iptables": {"status": "not_present"},
        "ip6tables": {"status": "not_present"},
        "ufw": {"status": "not_present"},
        "firewalld": {"status": "not_present"},
        "containers": {"status": "collected", "podman": []},
        "overlays": {"status": "collected"},
        "rule_files": {"status": "collected", "files": []},
    }


def test_a_live_host_page_scan_button_carries_that_host_name(tmp_path):
    """The live render interpolates the real host name into the button, so a
    click posts to that host's scan endpoint and not the sample's placeholder."""
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.execute(
        "INSERT INTO hosts (name, token_hash, created_at, last_report_at)"
        " VALUES (?, ?, ?, ?)",
        ("almabox", "hash-almabox", NOW.isoformat(), NOW.isoformat()))
    con.execute(
        "INSERT INTO reports (host_id, received_at, collected_at_unix, schema_version,"
        " document) VALUES (1, ?, ?, 1, ?)",
        (NOW.isoformat(), int(NOW.timestamp()), json.dumps(_minimal_document())))
    con.commit()
    con.close()

    html = rl.render(str(path), now=NOW)
    assert 'class="btn js-scan" data-host="almabox">Scan now<' in html
    # No sample host name leaks into the button, and no stale Check now stub.
    assert "Check now" not in html
    assert 'data-host="host"' not in html


def test_the_add_server_footer_says_cancel_until_something_happened():
    """The window opens on a picker, and a footer saying Done there reads as
    a step the reader missed (the 2026-08-29 audit round). The script flips
    it to Done exactly where an outcome appears: the command stage, and a
    created address host. reset() flips it back."""
    modal = build.add_server_modal()
    assert 'id="add-done">Cancel<' in modal
    html = build.build_sample()
    script = html[html.rindex("<script>"):]
    assert script.count("textContent='Done'") >= 3
    assert "done.textContent='Cancel'" in script
