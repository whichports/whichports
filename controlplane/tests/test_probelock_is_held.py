"""`probelock.is_held`: is a probing pass running from this machine right now.

The lock itself is held by tests/test_probe_lock.py. This file is the one
question the page asks of it.
"""

from app import probelock


# --------------------------------------------------- is a pass running right now
#
# The owner, 2026-09-10 and again 2026-09-20: a little circle going round while
# the probers run. Nothing stored says a pass is running, because a remote run
# is written only when it returns. The pass lock already is that fact, owned
# by the kernel: every lane and Scan now hold it for the whole of a pass
# (docs/RECORD.md 4.196). `is_held` asks without taking anything from a pass.

def test_no_lock_file_is_no_pass(tmp_path):
    assert probelock.is_held(str(tmp_path / "probe.lock")) is False


def test_a_lock_nobody_holds_is_no_pass(tmp_path):
    path = str(tmp_path / "probe.lock")
    with probelock.ProbeLock(path):
        pass
    assert probelock.is_held(path) is False


def test_a_held_lock_is_a_pass_and_it_ends_with_the_pass(tmp_path):
    path = str(tmp_path / "probe.lock")
    with probelock.ProbeLock(path):
        assert probelock.is_held(path) is True
    assert probelock.is_held(path) is False


def test_a_pass_holding_it_shared_is_a_pass(tmp_path):
    """`probe.ours` is held shared, by as many passes of ours as run, and
    the page's question still sees each of them."""
    path = str(tmp_path / probelock.OURS_FILENAME)
    with probelock.OurPass(path):
        with probelock.OurPass(path):
            assert probelock.is_held(path) is True
        assert probelock.is_held(path) is True
    assert probelock.is_held(path) is False


def test_asking_never_keeps_a_pass_from_starting(tmp_path):
    """Asked a hundred times, then a pass takes the lock at once: the check
    left nothing held behind it."""
    path = str(tmp_path / "probe.lock")
    with probelock.ProbeLock(path):
        pass
    for _ in range(100):
        assert probelock.is_held(path) is False
    with probelock.ProbeLock(path, wait_seconds=0):
        assert probelock.is_held(path) is True


def test_asking_does_not_create_the_file(tmp_path):
    """The page asks on every render. It must not leave a file in a directory
    a pass has never run in, and it opens the file read-only, which is all
    flock needs and all the process serving pages should have."""
    path = tmp_path / "probe.lock"
    probelock.is_held(str(path))
    assert not path.exists()


def test_nothing_to_lock_is_no_pass():
    assert probelock.is_held(None) is False


def test_a_path_that_cannot_be_opened_is_no_pass_and_never_an_error(tmp_path):
    """Not knowing is answered no. The mark says a pass is running, so it may
    only be drawn when one demonstrably is."""
    assert probelock.is_held(str(tmp_path)) is False            # a directory
    assert probelock.is_held(str(tmp_path / "no" / "such" / "probe.lock")) is False
