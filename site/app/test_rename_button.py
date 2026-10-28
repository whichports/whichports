"""The ID row in a server's settings, and the browser helpers the screen tests share.

Until 2026-10-03 this file tested the rename: the ID was a field with a Save,
and a rename repointed every control on the page at the new name. Decided
that day (docs/RECORD.md 4.298): the ID is what the agent first says, and a
constant. So the row is text now, and what is tested here is that nothing on
the page renames a server.

The file keeps its name because the other screen tests import their browser
helpers from it: `find_chrome`, `run_chrome`, `QuietHandler` and
`FileServer`. Renaming it is a change to every one of them and belongs in a
commit of its own.
"""
import functools
import html as html_mod
import http.server
import json
import os
import pathlib
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build  # noqa: E402
import render_live as rl  # noqa: E402


# The minimal control-plane schema, copied rather than imported so this file
# stands alone (the same posture test_mute_button.py takes and explains).
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

NOW = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)


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


def make_db(path):
    """One reporting host named almabox, with the report that makes the host
    page render its tabs, the settings among them."""
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
    return str(path)


# --------------------------------------------------------------- the markup







# --------------------------------------------------------------- the browser
#
# The page script is what carries the fix, and nothing else in the suite
# executes it. So a real browser drives the built page: serve it over http
# (the script does not run from file://), stub fetch inside the page, click
# rename twice, and read back where each request went.

CHROME_MAC = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# What the harness drives, and what it writes into #out for the test to read.
# Three renames: one that must repoint everything, one that must post to the
# repointed name, and a refused one that must move nothing.


def find_chrome():
    """The browser to drive with. The known path on the Mac this runs on, then
    the names CI's ubuntu image installs it under. Not finding one is a
    failure, never a skip: the gate allows no skips and this test is the only
    executed proof the fix works."""
    if os.path.exists(CHROME_MAC):
        return CHROME_MAC
    for name in ("google-chrome", "google-chrome-stable",
                 "chromium-browser", "chromium"):
        found = shutil.which(name)
        if found:
            return found
    pytest.fail("no Chrome or Chromium found, and the rename fix lives in "
                "page script that only a browser can execute")


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        # The request log would interleave with pytest's own output.
        pass


# **A page that asks for the product's fonts is served from a queue of 128**
# (2026-10-28). The page asks for its eight font files at once, and the
# standard library's server keeps a queue of only 5 connections waiting to
# be accepted. On a busy Mac the thread that accepts falls behind and the
# queue fills. macOS 27.0.1 then answers a new connection with a SYN cookie
# and a reset, and Chrome reports the font as failed: "IBM Plex Mono 400
# error" and "NetworkError: A network error occurred." in gates of 27 and 28
# October, each passing alone. Linux drops that SYN instead and the client
# sends it again until there is room. Measured that day with the accept loop
# half a second late and twelve clients: with a queue of 5, 70 fetches of 120
# failed on the Mac and none on Linux. With 128, none of 120 failed on
# either. 128 is the most macOS gives a listen queue (kern.ipc.somaxconn).
# Why a full queue answers on macOS: held_to_loopback in
# controlplane/tests/test_prober.py.
class FileServer(http.server.ThreadingHTTPServer):
    request_queue_size = 128


# **A start that prints nothing at all is started once more** (2026-10-03).
# Several gates that night failed on "Chrome produced no DOM dump before the
# timeout", one browser test at a time and a different one each time, and
# each passed when run again. The one hung start still alive to look at was a
# process Chrome had forked while starting, stuck for forty minutes on a lock
# inside fork's own clean-up (read with macOS `sample`), with the Chrome that
# forked it waiting on it and printing nothing. Nothing about the page, and
# nothing a longer wait would have fixed. Three hundred starts in a row, six
# at a time, all printed their page within 2.7 seconds. So a start that
# printed no line at all is tried once more with a profile of its own. A start
# that printed part of the page and stopped is not, because that one is about
# the page. What a page must show is asserted by its test, untouched.
#
# **Chrome's stderr is kept** and its last lines go into the failure, so the
# next one says why. And the whole process group is killed at the end: the
# stuck child above outlived the Chrome that was killed and was still there
# forty minutes later.
STDERR_LINES_SHOWN = 15


def run_chrome(cmd, timeout=120):
    """Run Chrome and collect its DOM dump without waiting for it to exit.

    Observed on the Mac this was written on: with --headless=new and a virtual
    time budget, Chrome prints the whole dump and then sometimes never exits,
    which turned this test into a two minute timeout. The dump ends at
    </html>, so this reads up to that line and then stops the browser itself.
    """
    dump, finished, stderr = start_chrome(cmd, timeout)
    if not dump:
        dump, finished, stderr = start_chrome(with_profile_of_its_own(cmd),
                                              timeout)
        assert dump, (f"Chrome printed nothing on two starts of {timeout} s"
                      " each. The last lines of the second one's stderr:\n"
                      + last_lines(stderr))
    assert finished, (f"Chrome printed part of the page and then nothing for"
                      f" {timeout} s. The last lines of its stderr:\n"
                      + last_lines(stderr))
    return dump


# One of Chrome's own built-in extensions keeps a worker busy in a headless
# Chrome for as long as it runs. Measured on 2026-10-03 with these tests'
# flags and Chrome 154: left running it took about 240 % of a core, and 0 %
# with this flag (docs/record 4.293). No page under test uses an extension.
NO_EXTENSIONS = "--disable-extensions"


def without_extensions(cmd):
    """The same command with Chrome's extensions off, said once."""
    if NO_EXTENSIONS in cmd:
        return list(cmd)
    return [cmd[0], NO_EXTENSIONS, *cmd[1:]]


def waited_for_the_page(done, timeout):
    """Whether Chrome got to the end of the page, or ended, within `timeout`
    seconds.

    A function of its own so that this helper's own tests can put what their
    stand-in for Chrome says in the place of the clock
    (test_chrome_helper.py). A test that gives a stand-in one second to
    start is a test of how busy the machine is, and one such test failed a
    gate on 2026-10-03 with two gates running (docs/record 4.314).
    """
    return done.wait(timeout)


def start_chrome(cmd, timeout):
    """One start. Returns what it printed up to </html>, whether it got
    there or ended, and its stderr."""
    with tempfile.TemporaryFile(mode="w+") as errors:
        # A process group of its own, so everything this start made, the
        # process it forked included, can be killed together.
        proc = subprocess.Popen(without_extensions(cmd),
                                stdout=subprocess.PIPE, stderr=errors,
                                text=True, start_new_session=True)
        lines = []
        done = threading.Event()

        def read():
            for line in proc.stdout:
                lines.append(line)
                if "</html>" in line:
                    break
            done.set()

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        try:
            finished = waited_for_the_page(done, timeout)
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                # The group is gone already. macOS answers EPERM rather than
                # ESRCH when all that is left of it is the leader that exited
                # and was not waited for yet, measured with a start that
                # crashed at once.
                pass
            proc.wait()
            reader.join(10)
        errors.seek(0)
        return "".join(lines), finished, errors.read()


def with_profile_of_its_own(cmd):
    """The same command with another profile directory, so the second start
    finds nothing the first one left behind."""
    return [f"{part}-again" if part.startswith("--user-data-dir=") else part
            for part in cmd]


def last_lines(stderr: str) -> str:
    lines = stderr.strip().splitlines()[-STDERR_LINES_SHOWN:]
    return "\n".join(lines) if lines else "(empty)"


# ------------------------------------------------------------------ the ID

def test_the_id_row_shows_the_id_as_text(tmp_path):
    html = rl.render(make_db(tmp_path / "cp.db"), now=NOW)
    assert '<span class="idv" id="id-almabox">almabox</span>' in html
    assert build.name_row("almabox", "almabox").count("<input") == 0


def test_nothing_on_the_page_renames_a_server(tmp_path):
    """No field, no Save, and no request to a server's rename route in the
    page script. A channel is still renamed, by its own route."""
    html = rl.render(make_db(tmp_path / "cp.db"), now=NOW)
    assert "js-rename" not in html
    assert 'id="rn-' not in html
    assert 'class="in mono js-name"' not in html
    script = html[html.rindex("<script>"):]
    assert re.search(r"/api/admin/hosts/'\+[^;]{0,80}\+'/rename'", script) is None
    assert "/api/admin/channels/" in script
