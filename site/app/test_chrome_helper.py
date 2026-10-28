"""How every browser test starts Chrome, held with a stand-in for Chrome.

    Run from site/app: python3 -m pytest test_chrome_helper.py

`run_chrome` in test_rename_button.py says why it starts Chrome a second time
when the first start printed nothing at all. These hold exactly that and no
more: a start that printed nothing is tried once more, a start that printed
part of the page is not, Chrome's stderr reaches the failure, and nothing a
start made outlives it. The stand-in is a small script that does what one
Chrome start did, so each case runs in a second, without a browser.
"""
import os
import pathlib
import sys
import textwrap
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import test_rename_button  # noqa: E402
from test_rename_button import (NO_EXTENSIONS, run_chrome,  # noqa: E402
                                without_extensions, with_profile_of_its_own)

# The helper's own wait, kept before the fixture below puts a stand-in's word
# in its place.
THE_CLOCK = test_rename_button.waited_for_the_page
# How long a stand-in may take to get anywhere at all. A limit and not a
# wait: no test comes near it unless the stand-in itself is broken.
LIMIT_SECONDS = 60


@pytest.fixture(autouse=True)
def the_stand_in_says_when_it_hangs(tmp_path, monkeypatch):
    """No test here waits on a wall clock for its stand-in.

    A stand-in that is going to print nothing more writes a line to
    `hanging` first. The helper's wait ends there, with the answer its
    timeout would give, and it ends at the page when the page comes. So a
    start has as long as the machine needs, and the seconds a test passes
    as `timeout` are only what the failure's sentence says.

    Why: with `timeout=1` the stand-in, a Python script, had one second to
    start, and with two gates running a second start once took longer than
    that. The test failed a gate that had nothing wrong in it
    (docs/record 4.314).
    """
    marker = tmp_path / "hanging"
    seen = {"hangs": 0}

    def until_the_page_or_the_hang(done, timeout):
        deadline = time.monotonic() + LIMIT_SECONDS
        while time.monotonic() < deadline:
            if done.wait(0.01):
                return True
            hangs = len(marker.read_text().split()) if marker.exists() else 0
            if hangs > seen["hangs"]:
                seen["hangs"] = hangs
                return done.is_set()
        return False

    monkeypatch.setattr(test_rename_button, "waited_for_the_page",
                        until_the_page_or_the_hang)

PAGE = "<html><body><p>the page</p></body>\n</html>\n"


def stand_in(tmp_path, behaviour: str) -> list:
    """A command that behaves like one Chrome start, chosen per start by
    `behaviour`, a list of words read in order. It counts its starts and
    writes the profile it was given to a file."""
    script = tmp_path / "chrome"
    script.write_text(textwrap.dedent(f"""\
        #!{sys.executable}
        import pathlib, subprocess, sys, time
        here = pathlib.Path({str(tmp_path)!r})
        starts = here / "starts"
        number = len(starts.read_text().split()) if starts.exists() else 0
        profile = [a for a in sys.argv[1:] if a.startswith("--user-data-dir=")]
        starts.write_text((starts.read_text() if starts.exists() else "")
                          + (profile[0] if profile else "none") + "\\n")
        flags = here / "flags"
        flags.write_text((flags.read_text() if flags.exists() else "")
                         + " ".join(a for a in sys.argv[1:]
                                    if a.startswith("--disable-")) + "\\n")
        plan = {behaviour.split()!r}
        what = plan[min(number, len(plan) - 1)]
        print("[1002/233103:ERROR] start " + str(number) + " is " + what,
              file=sys.stderr, flush=True)

        def hang():
            # Said before the sleep: nothing more is printed from here.
            with open(here / "hanging", "a") as marker:
                marker.write(str(number) + "\\n")
            time.sleep(600)
        if what == "page":
            print({PAGE!r}, end="", flush=True)
            time.sleep(600)  # Chrome that printed and does not exit
        elif what == "silent":
            hang()
        elif what == "half":
            print("<html><body>", flush=True)
            hang()
        elif what == "crash":
            sys.exit(1)
        elif what == "child":
            # A process this start leaves behind, the way the forked child
            # of the hung start did.
            child = subprocess.Popen([sys.executable, "-c",
                                      "import time; time.sleep(600)"])
            (here / "child").write_text(str(child.pid))
            hang()
        """))
    script.chmod(0o755)
    return [str(script), "--headless=new", f"--user-data-dir={tmp_path / 'profile'}",
            "--dump-dom", "http://127.0.0.1/page.html"]


def starts(tmp_path) -> list:
    return (tmp_path / "starts").read_text().split()


def gone(pid: int) -> bool:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def test_a_start_that_prints_the_page_is_the_only_start(tmp_path):
    assert run_chrome(stand_in(tmp_path, "page"), timeout=5) == PAGE
    assert len(starts(tmp_path)) == 1


def test_a_start_that_prints_nothing_is_tried_once_more_with_its_own_profile(tmp_path):
    assert run_chrome(stand_in(tmp_path, "silent page"), timeout=1) == PAGE
    first, second = starts(tmp_path)
    assert first == f"--user-data-dir={tmp_path / 'profile'}"
    assert second == f"--user-data-dir={tmp_path / 'profile'}-again"


def test_a_start_that_ends_at_once_with_nothing_is_tried_once_more_too(tmp_path):
    assert run_chrome(stand_in(tmp_path, "crash page"), timeout=5) == PAGE
    assert len(starts(tmp_path)) == 2


def test_two_silent_starts_fail_and_say_what_chrome_wrote(tmp_path):
    with pytest.raises(AssertionError) as failed:
        run_chrome(stand_in(tmp_path, "silent"), timeout=1)
    message = str(failed.value)
    assert "printed nothing on two starts of 1 s each" in message
    assert "start 1 is silent" in message, "the second start's stderr"
    assert len(starts(tmp_path)) == 2, "and not a third"


def test_part_of_a_page_is_the_pages_fault_and_is_not_started_again(tmp_path):
    """A start that printed something got Chrome running. What it did with
    the page is the test's to see, so it fails at once."""
    with pytest.raises(AssertionError) as failed:
        run_chrome(stand_in(tmp_path, "half page"), timeout=1)
    assert "printed part of the page and then nothing for 1 s" in str(failed.value)
    assert "start 0 is half" in str(failed.value)
    assert len(starts(tmp_path)) == 1


def test_what_a_start_leaves_behind_is_killed_with_it(tmp_path):
    with pytest.raises(AssertionError):
        run_chrome(stand_in(tmp_path, "child"), timeout=1)
    child = int((tmp_path / "child").read_text())
    assert gone(child), "the process the start made is gone too"


def test_a_start_that_succeeded_leaves_nothing_running_either(tmp_path):
    """The stand-in prints the page and keeps running, the way Chrome does."""
    assert run_chrome(stand_in(tmp_path, "page"), timeout=5) == PAGE
    # Its own process: the page was read, then the group was killed. A
    # second run with the same profile starts cleanly.
    assert run_chrome(stand_in(tmp_path, "page"), timeout=5) == PAGE


def test_every_start_runs_without_chromes_extensions(tmp_path):
    """The first start and the one made after a silent start: a built-in
    extension of Chrome's keeps a headless Chrome busy for as long as it
    runs, and no page under test uses one."""
    assert run_chrome(stand_in(tmp_path, "silent page"), timeout=1) == PAGE
    assert (tmp_path / "flags").read_text().splitlines() == [
        NO_EXTENSIONS, NO_EXTENSIONS]


def test_the_flag_goes_after_the_program_and_is_said_once():
    assert without_extensions(["chrome", "--headless=new", "x"]) == [
        "chrome", NO_EXTENSIONS, "--headless=new", "x"]
    already = ["chrome", "--headless=new", NO_EXTENSIONS, "x"]
    assert without_extensions(already) == already


def test_outside_these_tests_the_wait_is_the_clock():
    """What `start_chrome` calls when a real Chrome is behind it."""
    import inspect
    import threading
    done = threading.Event()
    assert THE_CLOCK(done, 0.05) is False
    done.set()
    assert THE_CLOCK(done, 0.05) is True
    assert "waited_for_the_page(done, timeout)" in inspect.getsource(
        test_rename_button.start_chrome)


def test_a_stand_in_that_never_says_it_hangs_is_given_up_on(tmp_path, monkeypatch):
    """The limit is there for a stand-in that is broken, so a test cannot
    wait for ever. Shortened here, or this test would take the minute."""
    monkeypatch.setattr(sys.modules[__name__], "LIMIT_SECONDS", 0.3)
    silent_for_ever = [sys.executable, "-c", "import time; time.sleep(600)"]
    with pytest.raises(AssertionError, match="printed nothing on two starts"):
        run_chrome(silent_for_ever, timeout=1)


def test_only_the_profile_argument_changes_for_the_second_start():
    cmd = ["chrome", "--headless=new", "--user-data-dir=/tmp/p", "--dump-dom", "x"]
    assert with_profile_of_its_own(cmd) == [
        "chrome", "--headless=new", "--user-data-dir=/tmp/p-again", "--dump-dom", "x"]
    assert with_profile_of_its_own(["chrome", "x"]) == ["chrome", "x"]


def test_every_browser_test_uses_this_one_helper():
    """Two copies drifted once: test_path_browser.py had its own, without
    the second start. Every browser test takes it from one place now."""
    import re
    here = pathlib.Path(__file__).resolve().parent
    defined = [path.name for path in sorted(here.glob("test_*.py"))
               if re.search(r"^def run_chrome\(", path.read_text(), re.M)]
    assert defined == ["test_rename_button.py"]
