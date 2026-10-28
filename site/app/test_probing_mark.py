"""A small turning mark beside a server's Probed fact while the probers run,
and Scan now that acts without a window.

The owner, 2026-09-10 and again 2026-09-20: a small indicator on the overview
says whether the probers are running, a circle going round, and a refresh of
the page is enough to update it. And of Scan now: pressing it makes the
probers scan, with no command to run on a server by hand.

What says a pass is running is `probe.ours`, which every lane and Scan now
hold shared for the whole of a pass (`controlplane/app/probelock.py`,
`is_held`),
and a scan somebody asked for that no pass has picked up yet
(`scan_requests.drained_at`). No tick when it is done: docs/DESIGN.md section
3 allows none, so done is the mark gone and the age beside it, as on the Add
server window.
"""
import pathlib
import sqlite3
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return str(path)


def two_servers(db):
    for name in ("media-01", "student-net"):
        trl.reporting(db, name, trl.document(listening=[trl.SSHD]))
        trl.probe_result(db, name, 22, "v4", "no_response")


def probed_fact(html, name):
    view = html[html.index(f'id="host-{name}"'):]
    start = view.index('data-probed="')
    return view[view.rindex("<div", 0, start):view.index("</div></div>", start)]


def a_pending_scan(db, name):
    scan = rl.joinbridge.module("scan")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    scan.init(con)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]
    assert scan.request_scan(con, host_id, now=NOW).accepted
    con.close()


def test_with_nothing_running_no_fact_says_probing(db):
    two_servers(db)
    html = rl.render(db, now=NOW)
    for name in ("media-01", "student-net"):
        assert "probing" not in probed_fact(html, name).split(">")[0]


def test_a_pass_holding_the_lock_marks_every_server(db):
    """A pass covers the fleet, so while one runs every server is being
    probed or about to be."""
    two_servers(db)
    probelock = rl.joinbridge.module("probelock")
    with probelock.OurPass(str(pathlib.Path(db).parent / probelock.OURS_FILENAME)):
        html = rl.render(db, now=NOW)
    for name in ("media-01", "student-net"):
        assert 'class="f probing"' in probed_fact(html, name)
    after = rl.render(db, now=NOW)
    assert 'class="f probing"' not in after


def test_the_whole_pass_lock_alone_marks_nothing(db):
    """`probe.lock` is held by the worker that serves self-hosted
    instances, and their servers are not on this page. The mark reads
    `probe.ours` and nothing else."""
    two_servers(db)
    probelock = rl.joinbridge.module("probelock")
    with probelock.ProbeLock(str(pathlib.Path(db).parent / probelock.LOCK_FILENAME)):
        html = rl.render(db, now=NOW)
    assert 'class="f probing"' not in html


def test_a_scan_asked_for_and_not_picked_up_marks_that_server_alone(db):
    two_servers(db)
    a_pending_scan(db, "student-net")
    html = rl.render(db, now=NOW)
    assert 'class="f probing"' in probed_fact(html, "student-net")
    assert 'class="f probing"' not in probed_fact(html, "media-01")


def test_the_mark_is_in_every_probed_fact_and_drawn_only_while_probing(db):
    """Written always, hidden by the stylesheet, so the click can show it at
    once without building anything."""
    two_servers(db)
    fact = probed_fact(rl.render(db, now=NOW), "media-01")
    assert 'data-probed="media-01"' in fact
    assert '<span class="pspin"' in fact and 'title="probing"' in fact
    assert ".pspin{display:none" in build.CSS
    assert ".f.probing .pspin{display:inline-block" in build.CSS


def test_the_mark_is_never_a_tick(db):
    two_servers(db)
    fact = probed_fact(rl.render(db, now=NOW), "media-01")
    for glyph in ("✓", "✔", "check"):
        assert glyph not in fact


# ---------------------------------------------------------------- Scan now

def script(html):
    start = html.rindex("<script>")
    return html[start:html.index("</script>", start)]


def test_scan_now_opens_no_window_and_hands_over_no_command(db):
    """docs/screens/host-overview/SPEC.md: "Scan now shows its result in the
    header and in the marks, with no dialog." The window had been kept on
    2026-09-06 to hold the one-shot command. He found that command weird on
    2026-09-20, rightly: the agent reports by itself every fifteen minutes."""
    two_servers(db)
    html = rl.render(db, now=NOW)
    assert "scan-ovl" not in html
    assert "whichports-agent --mode=oneshot" not in html
    assert "Asking the prober" not in html


def test_the_click_marks_the_fact_at_once_and_a_refusal_is_said(db):
    two_servers(db)
    js = script(rl.render(db, now=NOW))
    assert "classList.add('probing')" in js
    # a refusal is the control plane's own sentence, as a toast
    assert "toast(r.body.sentence" in js
    # and the page asks for itself afterwards, so the age and the marks follow
    assert "refresh(true)" in js[js.index(".js-scan"):js.index(".js-scan") + 1500]
