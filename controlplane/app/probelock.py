"""The locks that keep two of our runners off one target, whoever asked.

## Why this exists

`docs/PRODUCT.md` 5d promises that a target host receives about 40 connects a
second from us in total, across every vantage point. The pace that keeps that
promise lives in `prober.Prober`, one bucket per target inside one process, and
nothing bounded what two processes did. `whichports-probe-fast.timer` fires
every ten minutes, `whichports-probe.timer` every hour, each with a random
delay, and `whichports-scan.service` whenever somebody clicks Scan now. All
three run the same pass. Two of them landing together put two full allowances
on the same host, and every vantage they drove added another.

Measured on 2026-09-12 with the real dispatcher and the real runner in process,
one host of 100 ports and two vantages: one pass put at most 80 connects on the
target in any one second, two passes at once put 161, three put 239.

## What it was, and still is on a self-hosted instance

An advisory lock on one file beside the database, `probe.lock`, held with
`flock(2)` for the whole of a pass by every command that puts packets on the
wire from this machine: `prober_cli probe` in each of its three modes and
`scan_cli drain`. A second pass waits its turn. The wait is bounded so a pass
that hangs cannot stack timers up behind it forever, and a pass that gives up
exits non-zero having sent nothing. Since the finer locks below, only a
self-hosted instance holds it whole for a pass, because our API takes one of
its batches at a time (`dispatch.uses_prober_api`). On our box each batch
takes the finer locks instead.

## Why flock and not something cleverer

The kernel owns it. flock(2), read 2026-09-12: "The lock is released either by
an explicit LOCK_UN operation on any of these duplicate file descriptors, or
when all such file descriptors have been closed", and a process that dies
closes its descriptors. So there is no lease to expire, no row to clean up
after a crash, no schema, and no unit file to change: the file sits in the
directory the three units already name in `ReadWritePaths`.

Two descriptors on one file are two locks, even in one process, from the same
page: "If a process uses open() to obtain more than one file descriptor for
the same file, these file descriptors are treated independently by flock()."
That is what lets the tests run two passes as two threads and have them
exclude each other exactly as two processes do.

## The honest limit

The lock is on this machine. A pass driven from another machine, a laptop
running `prober_cli probe` against a copy of the database while the
production timers run, cannot see it. `ops/RUNBOOK.md` carries that rule,
because no code on this box can enforce it.

A database that lives in memory has no directory, and no second process can
share it, so a connection to one gets a lock that guards nothing and says so.
Only the tests open those.

## The finer locks, phase 1 of docs/SPEC-probe-locks.md

One lock for everything meant one batch at a time from this box, on either
prober, whoever asked: probe1 waited while probe2 ran a batch for another
server. Two kinds of lock replace it for a batch, each a file in a directory
beside the database, and a batch takes all of its locks or none:

  - **one per prober**, `probe.prober/<id>`, the id of the vantage's row in
    the registry and never a name a command typed. A prober runs one batch
    of ours at a time, as it always has, and now beside the other prober.
  - **one per address**, striped: 4096 files `probe.stripes/0000` to `4095`,
    an address's stripe read from the SHA-256 of the address as
    `authz.normalise_target` writes it. A target never has two of our
    runners against it at once, from one prober or two (docs/PRODUCT.md 5d).
    Two addresses on one stripe wait for each other, which costs time and
    never the promise. No file name carries an address.

**All or none, without waiting.** Every lock is asked for with `LOCK_NB`.
When one is not free, every one already taken is let go before the batch
asks again a poll later. A batch never waits while it holds a lock, so no two
batches can each hold what the other waits for.

**And `probe.lock`, shared.** Every set of the finer locks also holds
`probe.lock` shared, so a process that holds it whole, a self-hosted
instance's pass or a process of the code before these locks still running
through a deploy, keeps every batch of ours out while it runs, and is kept
out by them.

**And `probe.ours`, for the page.** Every pass of ours holds `probe.ours`
shared for its whole length, and the page's mark asks it (`is_held`). The
worker that serves self-hosted instances never takes it, so their batches
mark no server of ours.
"""
import dataclasses
import fcntl
import hashlib
import os
import sqlite3
import time

from . import authz

LOCK_FILENAME = "probe.lock"

# Held shared by every pass of ours for its whole length, and read by the
# page's mark (`is_held`). Nothing else takes it, so a batch the worker runs
# for a self-hosted instance marks no server of ours.
OURS_FILENAME = "probe.ours"

# The finer locks' directories, beside the database (see the top).
PROBERS_DIRECTORY = "probe.prober"
STRIPES_DIRECTORY = "probe.stripes"

# How many address stripes, the spec's number. Two addresses on one stripe
# wait for each other only when both are in batches at the same moment, and
# two batches of two addresses each meet that way by chance about once in a
# thousand (4 pairs in 4096). It costs a wait, never the promise.
STRIPES = 4096

# How long a pass waits for the one before it. A pass over the whole fleet
# takes seconds today and minutes at a thousand hosts, so half an hour means
# something is wrong, and the timers do not queue up behind it: systemd does
# not start a timer's service while the previous run is still active, so at
# most one fast, one hourly and one scan can ever be waiting.
WAIT_SECONDS = 30 * 60

# How often a waiting pass asks again. Coarse on purpose: a second of latency
# on a ten minute lane is nothing, and a tight loop would be a busy wait.
POLL_SECONDS = 1.0

# The exit code for a pass that gave up waiting for `probe.lock` held whole,
# which only a self-hosted instance's passes take, and for a worker that
# finds another worker. 1 is a pass that ran and did not measure everything,
# 2 is a refusal to start on bad arguments; this is neither. On our box a
# batch that gives up waiting for its finer locks costs that host only, so
# its pass exits 1, and each such batch writes one `HELD_LINE` to the
# journal: a grep for that, or for this exit, finds exactly the overlaps.
EXIT_HELD = 3

# The start of the one line a batch writes when it gave up waiting for its
# locks (`held_line`).
HELD_LINE = "probe lock held"


class ProbeLockHeld(RuntimeError):
    """Another pass held the lock for the whole wait. Nothing was sent."""


class ProberBusy(ProbeLockHeld):
    """A batch's prober stayed busy for the whole wait, or a pass held
    `probe.lock` whole for it. Nothing was sent."""
    kind = "prober_busy"


class AddressBusy(ProbeLockHeld):
    """Another batch held one of this batch's addresses for the whole wait.
    Nothing was sent."""
    kind = "address_busy"


def held_line(exc: ProbeLockHeld, vantage: str, host_id: int | None) -> str:
    """The journal's line for one batch that gave up waiting for its locks:
    the class, the vantage and the server's number, and never an address,
    so a grep for `HELD_LINE` counts the overlaps and names nothing we
    probe. `host_id` None is the worker's thread, whose wait is for its
    prober and not for one server."""
    kind = getattr(exc, "kind", "pass_busy")
    where = "worker" if host_id is None else f"host_id={host_id}"
    return f"{HELD_LINE}: {kind} vantage={vantage} {where}"


def directory_for(con: sqlite3.Connection) -> str | None:
    """The directory of the database `con` is open on, where every lock of
    this file lives.

    None for a database that lives in memory, which has no directory. Read
    from the connection rather than from `WHICHPORTS_DB`, so a command handed
    a connection by a test locks beside that database and nothing else.
    """
    for row in con.execute("PRAGMA database_list"):
        # Columns: seq, name, file. The main database is the one the lock
        # guards; an attached one is nobody's box.
        if row[1] != "main":
            continue
        file = row[2]
        if not file:
            return None
        return os.path.dirname(os.path.abspath(file))
    return None


def lock_path_for(con: sqlite3.Connection) -> str | None:
    """The lock file beside the database `con` is open on, or None for a
    database in memory."""
    directory = directory_for(con)
    return None if directory is None else lock_path_in(directory)


def lock_path_in(directory: str) -> str:
    return os.path.join(directory, LOCK_FILENAME)


def ours_path_for(con: sqlite3.Connection) -> str | None:
    """`probe.ours` beside the database `con` is open on, or None for a
    database in memory."""
    directory = directory_for(con)
    return None if directory is None else os.path.join(directory, OURS_FILENAME)


def _checked_prober(prober) -> int:
    """A vantage's row id, or ValueError. A name would let two names for one
    box take two locks, so only the registry's own number is a key."""
    if isinstance(prober, bool) or not isinstance(prober, int) or prober < 1:
        raise ValueError(f"a prober's lock is keyed on its registry row id, not {prober!r}")
    return prober


def prober_path(directory: str, prober: int) -> str:
    return os.path.join(directory, PROBERS_DIRECTORY, str(_checked_prober(prober)))


def stripe_of(address) -> int | None:
    """The stripe of one address, 0 to STRIPES - 1, or None for a target
    that is not an address, which the engine records as not tested and
    connects to nothing.

    Read from the address as `authz.normalise_target` writes it, the
    registry's own spelling, so two spellings of one address are one stripe.
    65536 is a multiple of 4096, so the first two bytes of the digest spread
    evenly over the stripes."""
    try:
        canonical, _family = authz.normalise_target(address)
    except authz.TargetError:
        return None
    digest = hashlib.sha256(canonical.encode("ascii")).digest()
    return int.from_bytes(digest[:2], "big") % STRIPES


def stripe_path(directory: str, stripe: int) -> str:
    return os.path.join(directory, STRIPES_DIRECTORY, f"{stripe:04d}")


def is_held(path: str | None) -> bool:
    """Whether a probing pass of ours is running from this machine right now.

    For the page, which draws a mark beside a server's Probed fact while one
    is (docs/RECORD.md 4.196), and which asks it of `probe.ours`
    (`ours_path_for`). Nothing stored can answer this, because a remote run
    is written only when it returns. The lock can: every lane and Scan now
    hold it shared for the whole of a pass, and the kernel drops it when the
    process ends, however it ends.

    It asks for the lock exclusive without waiting. While any pass holds it,
    shared or whole, that is refused, which is the answer yes. When it is
    granted it is given straight back. A pass that starts in that instant
    waits that instant for its shared lock, so asking costs a pass nothing it
    notices. flock(2), read 2026-10-28: "A shared or exclusive lock can be
    placed on a file regardless of the mode in which the file was opened."

    The file is opened read-only and never created, because the process that
    serves pages asks on every render and should neither need to write here
    nor leave a file where no pass ever ran.

    **Not knowing is no.** No file, no path, a path that cannot be opened:
    all False, and no exception. The mark claims a pass is running, so it is
    drawn only when one demonstrably is.
    """
    if path is None:
        return False
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        except OSError:
            return False
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


class OurPass:
    """`probe.ours`, held shared for the length of a `with` block: one pass
    of ours, for the page's mark. Many passes of ours hold it at once.

    It waits for the lock without a limit, because the only one that ever
    takes it whole is `is_held`, without waiting and for an instant. It is
    taken before any other lock of a pass, so the pass holds nothing else
    while it waits. `path` None, from a database in memory, takes nothing.
    """

    def __init__(self, path: str | None) -> None:
        self.path = path
        self._fd: int | None = None

    @classmethod
    def for_connection(cls, con: sqlite3.Connection) -> "OurPass":
        return cls(ours_path_for(con))

    def __enter__(self) -> "OurPass":
        if self.path is not None:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
            try:
                fcntl.flock(fd, fcntl.LOCK_SH)
            except BaseException:
                os.close(fd)
                raise
            self._fd = fd
        return self

    def __exit__(self, *exc) -> None:
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None


class ProbeLock:
    """Hold the pass lock for the length of a `with` block.

    `path` None means there is nothing to lock, which only an in-memory
    database produces. `guards_nothing` says so, so a test can check it is
    looking at the case it thinks it is.
    """

    def __init__(self, path: str | None, *, wait_seconds: float = WAIT_SECONDS,
                 poll_seconds: float = POLL_SECONDS,
                 clock=time.monotonic, sleep=time.sleep) -> None:
        if wait_seconds < 0:
            raise ValueError("wait_seconds cannot be negative")
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be positive")
        self.path = path
        self.guards_nothing = path is None
        self._wait = wait_seconds
        self._poll = poll_seconds
        self._clock = clock
        self._sleep = sleep
        self._fd: int | None = None

    @classmethod
    def for_connection(cls, con: sqlite3.Connection, **kwargs) -> "ProbeLock":
        return cls(lock_path_for(con), **kwargs)

    def __enter__(self) -> "ProbeLock":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()

    def acquire(self) -> None:
        if self.path is None:
            return
        # Created if missing, never truncated: the file's content is nothing
        # and only its existence matters. 0o644 so the operator can see it
        # with ls and nothing else can take it.
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        started = self._clock()
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if self._clock() - started >= self._wait:
                    os.close(fd)
                    raise ProbeLockHeld(
                        f"another probing pass has held {self.path} for"
                        f" {self._wait:g} seconds, so this one sent nothing."
                        " A pass that is still running is the usual reason;"
                        " a pass that died releases the lock by itself")
                self._sleep(self._poll)
                continue
            self._fd = fd
            return

    def release(self) -> None:
        if self._fd is None:
            return
        # Closing releases the lock on its own (flock(2)); the explicit unlock
        # is so the order of events is visible to a reader.
        fcntl.flock(self._fd, fcntl.LOCK_UN)
        os.close(self._fd)
        self._fd = None


# ------------------------------------------------------- the finer locks

# What `Locks.try_acquire` found in its way, when it did not take them all.
BUSY_PASS = "pass"          # probe.lock, held whole by a pass
BUSY_PROBER = "prober"      # the batch's prober
BUSY_ADDRESS = "address"    # one of the batch's addresses


class Locks:
    """Every lock one batch holds, taken all or none (see the top).

    `prober` is the vantage's row id, or None for a batch that names no
    prober: the local mode, which probes from this machine, and a worker
    thread's batch, whose thread already holds its prober's lock.
    `addresses` are the targets the batch may connect to. `pass_lock` takes
    `probe.lock` shared beside them, and only a worker thread's batch leaves
    it out, for the same reason it leaves out the prober.

    `directory` None means there is nothing to lock, which only an in-memory
    database produces, and `guards_nothing` says so.
    """

    def __init__(self, directory: str | None, *, prober: int | None = None,
                 addresses=(), pass_lock: bool = True,
                 wait_seconds: float = WAIT_SECONDS,
                 poll_seconds: float = POLL_SECONDS,
                 clock=time.monotonic, sleep=time.sleep) -> None:
        if wait_seconds < 0:
            raise ValueError("wait_seconds cannot be negative")
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be positive")
        if prober is not None:
            _checked_prober(prober)
        self.directory = directory
        self.guards_nothing = directory is None
        self._wait = wait_seconds
        self._poll = poll_seconds
        self._clock = clock
        self._sleep = sleep
        self._wanted = []
        if directory is not None:
            if pass_lock:
                self._wanted.append((lock_path_in(directory), fcntl.LOCK_SH, BUSY_PASS))
            if prober is not None:
                self._wanted.append((prober_path(directory, prober), fcntl.LOCK_EX,
                                     BUSY_PROBER))
            # Each stripe once: two descriptors of one file exclude each other
            # even in one process (flock(2)), so a batch whose two addresses
            # share a stripe would otherwise wait for itself.
            stripes = {stripe_of(address) for address in addresses} - {None}
            for stripe in sorted(stripes):
                self._wanted.append((stripe_path(directory, stripe), fcntl.LOCK_EX,
                                     BUSY_ADDRESS))
        self._held: list[int] = []

    def __enter__(self) -> "Locks":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()

    def try_acquire(self) -> str | None:
        """Take every lock now or none of them. None when all are held,
        otherwise what was in the way, `BUSY_PASS`, `BUSY_PROBER` or
        `BUSY_ADDRESS`, with nothing held."""
        if self._held:
            raise RuntimeError("these locks are already held")
        try:
            for path, mode, kind in self._wanted:
                os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
                # Created if missing, never truncated, as `ProbeLock` does.
                fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
                try:
                    fcntl.flock(fd, mode | fcntl.LOCK_NB)
                except BaseException:
                    os.close(fd)
                    raise
                self._held.append(fd)
        except BlockingIOError:
            self.release()
            return kind
        except BaseException:
            # A lock that could not even be opened, a full disk or a file
            # another user made: everything taken before it is let go, so
            # the error never leaves a lock held behind it.
            self.release()
            raise
        return None

    def acquire(self) -> None:
        """Ask again every poll until every lock is held, for at most the
        wait. A wait that runs out raises `ProberBusy` or `AddressBusy`,
        for the lock that was in the way last, with nothing held."""
        started = self._clock()
        while True:
            busy = self.try_acquire()
            if busy is None:
                return
            if self._clock() - started >= self._wait:
                if busy == BUSY_ADDRESS:
                    raise AddressBusy(
                        f"another batch held an address of this one for"
                        f" {self._wait:g} seconds, so this batch was not sent")
                raise ProberBusy(
                    f"the prober was busy for {self._wait:g} seconds, so this"
                    " batch was not sent")
            self._sleep(self._poll)

    def release(self) -> None:
        """Let go of every lock held, in the reverse order they were taken.
        Harmless when none is."""
        while self._held:
            fd = self._held.pop()
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


@dataclasses.dataclass(frozen=True)
class BatchLocks:
    """How every batch of one pass takes its locks: where they live, which
    prober, and how long a batch waits. `dispatch.run_pass` sets the prober
    per vantage with `on_prober`, and `taking` gives one batch its `Locks`."""
    directory: str | None
    prober: int | None = None
    wait_seconds: float = WAIT_SECONDS
    poll_seconds: float = POLL_SECONDS

    @classmethod
    def for_connection(cls, con: sqlite3.Connection, **kwargs) -> "BatchLocks":
        return cls(directory_for(con), **kwargs)

    def on_prober(self, prober: int) -> "BatchLocks":
        return dataclasses.replace(self, prober=_checked_prober(prober))

    def taking(self, addresses) -> Locks:
        return Locks(self.directory, prober=self.prober, addresses=addresses,
                     wait_seconds=self.wait_seconds, poll_seconds=self.poll_seconds)
