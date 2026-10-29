"""Drive our probers for the batches self-hosted instances queued.

    python -m app.proberapi_worker            # runs until stopped, the unit's mode
    python -m app.proberapi_worker --once     # one round, then exit

`app/proberapi.py` owns the queue and the reasoning. This is the half that
reaches the vantage hosts, and it is a process of its own for one reason.

## Why the API does not probe

**The ingest faces the internet and has no ssh access, and never gets one**
(`ops/RUNBOOK.md`, the scan units). The key it would need is root on probe1
and probe2, and whoever holds it can hand a runner any snapshot at all. So the
routes in the ingest only check, charge and queue, and this process, which
nothing outside the box can reach, builds the snapshot and sends the batch.
It is the split Scan now already has, with a queue table where Scan now has a
trigger file, because an instance is waiting on the other end for the answer.

## One thread per prober, one batch at a time on each

Phase 1 of docs/SPEC-probe-locks.md. Each prober in the registry has a thread
of its own, and each thread holds its prober's lock (`app/probelock.py`, the
finer locks) while it runs that prober's batches, so probe1 serves one
instance while probe2 serves another, and neither prober ever runs two
batches of ours at once. Each batch also holds the stripes of its addresses,
the same locks every pass of ours takes, so a target never has two of our
runners against it, whichever instances asked and whichever vantages they
named (`docs/PRODUCT.md` 5d).

A thread starts no batch after `HOLD_SECONDS` of holding its prober's lock,
so it holds it for that and the batch it started last, and then lets go for
`YIELD_SECONDS`, because flock(2) is not fair: a process that lets go and
takes it again at once can keep a waiting timer out for as long as the queue
is full. A pass waiting on it asks again every `probelock.POLL_SECONDS`, so a
pause of twice that is always long enough for it to get in.

**Our passes first.** A pass of ours lets go of a prober between its batches,
so under full queues it would wait about one hold and one yield for every
server on every prober (the code challenge of 2026-10-28, finding 3). So the
worker steps aside while any pass of ours runs, which it reads off
`probe.ours`, the lock every pass of ours holds for its whole length: a
thread starts no round and no batch while it is held. A pass then waits for
at most the batch each thread was running when it started, as it did under
the one lock, and instances wait for our passes, as they did.

**A thread that meets an error of no known kind ends the worker.** systemd
starts it again five seconds later, and its first act closes the batch the
thread had claimed as `interrupted`, as before there were threads. A thread
that died quietly would leave its prober to nobody until the unit was
restarted. A thread whose prober left the registry, or came back as another
row, ends by itself, and the new row gets a thread of its own.

**The order, for every batch.** The stripes of the addresses our registry
allows the instance, all or none. A batch whose stripes are busy is passed
over for this round and stays queued, so the thread never waits while it
holds a lock. Then the claim (`mark_started`), then the instance, the vantage
and our own addresses read again, then the snapshot, built from the locked
addresses alone, then the abuse log, then the send. So a revoke or an
exclusion that lands while a batch waits holds for that batch.

## One worker at a time

The worker holds `proberapi.worker`, beside the database, for its whole life.
A second one, started by hand, finds it held and exits at once, before it
closes anything: closing what it thinks the last stop cut off would close
the first worker's running batches.

## Stopping

SIGTERM, which is what `systemctl restart` sends, lets the batch that is
running finish and then stops, so a deploy never cuts a batch in half. A
batch cut off anyway, by a kill or a crash, is closed as `interrupted` when
the worker next starts, which frees that instance's slot at once rather than
fifteen minutes later.

## What reaches the runner

The instance's batch, with one thing replaced: the snapshot. It is built here
from our registry, under the instance's account, for only the addresses the
instance's own snapshot allowed (`app/proberapi.py`, "can only narrow"). The
addresses and ports go as the instance sent them, so the runner answers for
every address, and one that is not allowed comes back not tested with
`no_authorization`, exactly as it does on an ssh pass. The answer goes back
verbatim, after it has been checked to be a measurement.
"""

import argparse
import fcntl
import json
import logging
import os
import signal
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone

from . import (authz, cli, db, dispatch, instances, probelock, prober,
               proberapi, vantages)

log = logging.getLogger(__name__)

# How long a prober's lock is held for one round of batches before it is let go.
HOLD_SECONDS = 30.0

# How long it is let go for. Twice a waiting pass's poll, so it gets in.
YIELD_SECONDS = 2 * probelock.POLL_SECONDS

# How often an empty queue is asked again. The instance polls its answer
# every second, so a second here keeps the wait it sees to about two.
IDLE_POLL_SECONDS = 1.0

# The worker's life lock, beside the database (see the top).
WORKER_LOCK_FILENAME = "proberapi.worker"


def _now() -> datetime:
    return datetime.now(timezone.utc)


class WorkerLock:
    """`proberapi.worker`, held for the whole life of one worker, taken
    without waiting. The kernel lets go of it when the process ends, however
    it ends (flock(2)), so a worker that died never keeps the next one out.
    `path` None, from a database in memory, guards nothing."""

    def __init__(self, path: str | None) -> None:
        self.path = path
        self._fd: int | None = None

    @classmethod
    def for_connection(cls, con: sqlite3.Connection) -> "WorkerLock":
        directory = probelock.directory_for(con)
        return cls(None if directory is None
                   else os.path.join(directory, WORKER_LOCK_FILENAME))

    def try_acquire(self) -> bool:
        if self.path is None:
            return True
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return False
        self._fd = fd
        return True

    def release(self) -> None:
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None


def _allowed(request: proberapi.BatchRequest) -> list:
    """The batch's addresses that the instance's own snapshot allowed, in the
    spelling the batch used. Only these are asked about in our registry, so
    ours can narrow theirs and theirs can narrow ours, and neither can widen
    the other."""
    theirs = set(request.allowed)
    kept = []
    for address in request.addresses:
        try:
            canonical, _family = authz.normalise_target(address)
        except authz.TargetError:
            continue
        if canonical in theirs:
            kept.append(address)
    return kept


def allowed_by_us(con: sqlite3.Connection, row, now: datetime) -> list:
    """The batch's addresses that its instance's own snapshot allowed and our
    registry allows that instance now, in the spelling the batch used. These
    are the addresses whose stripes the batch takes, and the only ones its
    snapshot can hold (docs/SPEC-probe-locks.md, point 3), so an instance
    cannot keep an address it never proved to us waiting. Empty for an
    instance gone or revoked, whose batch is dropped once it is claimed."""
    instance = instances.by_id(con, row["instance_id"])
    if instance is None or instance.revoked_at:
        return []
    request = proberapi.BatchRequest.from_json(row["request"])
    return [address for address in _allowed(request)
            if authz.may_probe(con, address, now=now,
                               account=instance.account).allowed]


def run_batch(con: sqlite3.Connection, row, transport_factory,
              now: datetime, *, prober_id: int, locked) -> str:
    """Run one claimed batch and record what came of it. Returns the outcome,
    `done`, `dropped` or a failure class, for the journal and the tests.

    `prober_id` is the registry row whose lock the thread holds, and a
    vantage that is no longer that row is not sent to. `locked` is the
    addresses whose stripes the batch holds (`allowed_by_us`), the most its
    snapshot may hold. Every read below happens after the locks."""
    instance = instances.by_id(con, row["instance_id"])
    if instance is None or instance.revoked_at:
        # Revoked after it queued. Nothing is sent, and nobody can collect
        # it, because the key that would is refused.
        proberapi.drop(con, row)
        return "dropped"

    request = proberapi.BatchRequest.from_json(row["request"])
    vantage = vantages.by_name(con, request.vantage)
    if vantage is None or not vantage.enabled or vantage.id != prober_id:
        proberapi.record_failure(con, row, "vantage_unreachable", now)
        return "vantage_unreachable"

    # Checked again here and not only at the door, because the registry can
    # gain an address while a batch waits. A vantage never probes itself or
    # another vantage (app/vantages.py).
    _kept, ours = dispatch.split_targets(request.addresses,
                                         vantages.all_addresses(con))
    if ours:
        proberapi.record_failure(con, row, "names_a_vantage_address", now)
        return "names_a_vantage_address"

    allowed = list(locked)
    # `dispatch.build_batch` is the one owner of the batch's shape and the
    # one place a snapshot is read for a batch, so it builds this one too,
    # under the instance's account and for the locked addresses only. Then
    # every address the instance sent goes back in, so the runner answers for
    # each of them, and the ones outside the snapshot are refused by it.
    payload = dispatch.build_batch(con, vantage.name, allowed, request.ports,
                                   tls_ports=request.tls_ports, now=now,
                                   account=instance.account)
    payload["addresses"] = list(request.addresses)
    probed = sorted(payload["snapshot"]["targets"])

    # In the log before it is sent, so a batch whose answer is lost is still
    # a batch an abuse report can find.
    proberapi.log_sent(con, instance.id, vantage.name, probed,
                       request.per_address(), now)

    transport = transport_factory(vantage.destination)
    try:
        raw = transport(json.dumps(payload))
    except dispatch.VantageUnreachable as exc:
        log.warning("batch %s for %s: %s", row["id"], instance.name, exc)
        proberapi.record_failure(con, row, "vantage_unreachable", _now())
        return "vantage_unreachable"
    except dispatch.DispatchFailed as exc:
        log.warning("batch %s for %s: %s", row["id"], instance.name, exc)
        proberapi.record_failure(con, row, "prober_refused", _now())
        return "prober_refused"

    try:
        prober.run_from_json(json.loads(raw))
    except (ValueError, prober.RunUnreadable) as exc:
        log.warning("batch %s for %s: the prober's answer is unusable: %s",
                    row["id"], instance.name, exc)
        proberapi.record_failure(con, row, "prober_answer_unreadable", _now())
        return "prober_answer_unreadable"

    proberapi.record_answer(con, row, raw.strip(), _now())
    return "done"


def _close_as_interrupted(con: sqlite3.Connection, row) -> None:
    """A batch the database stopped part way. Closed as `interrupted` so
    its instance's one slot is free, if the database lets that be written.
    If it does not, the batch goes when its fifteen minutes are up."""
    try:
        proberapi.record_failure(con, row, "interrupted", _now())
    except sqlite3.Error as exc:
        log.warning("batch %s could not be closed: %s", row["id"],
                    type(exc).__name__)


def _waited(submitted_at: str, start: datetime) -> float:
    """Seconds from a batch's queueing to its start, or 0 when the stamp
    cannot be read, which only a hand-edited row can do."""
    try:
        queued = datetime.fromisoformat(submitted_at)
    except (TypeError, ValueError):
        return 0.0
    if queued.tzinfo is None:
        queued = queued.replace(tzinfo=timezone.utc)
    return max(0.0, (start - queued).total_seconds())


def _start_and_run(con: sqlite3.Connection, row, vantage, transport_factory,
                   clock, now) -> str | None:
    """One batch of the prober whose lock the caller holds, in the order at
    the top. None when it was not started, because one of its addresses was
    busy or it was claimed already, with nothing held and the batch as it
    was."""
    locked = allowed_by_us(con, row, now())
    stripes = probelock.Locks(probelock.directory_for(con), addresses=locked,
                              pass_lock=False)
    if stripes.try_acquire() is not None:
        return None
    try:
        start = now()
        if not proberapi.mark_started(con, row["id"], start):
            return None
        began = clock()
        try:
            outcome = run_batch(con, row, transport_factory, now(),
                                prober_id=vantage.id, locked=locked)
        except sqlite3.OperationalError:
            _close_as_interrupted(con, row)
            raise
        held = clock() - began
        # Charged to the instance whatever came of the batch: a batch the
        # prober refused held its prober's lock all the same. The pace
        # refuses an instance whose batches held one too long in the last
        # hour (`proberapi.LOCK_SECONDS_PER_HOUR`).
        proberapi.charge_lock_seconds(con, row["id"], held)
        # The time each batch took and how long it waited in the queue before
        # that, in the journal, because what one batch costs is what decides
        # how many instances the probers can carry, and it is measured on the
        # box rather than guessed (RUNBOOK). The instance by its number, the
        # vantage and the outcome class, and nothing the instance sent.
        log.info("batch for instance %s from %s: %s in %.1f s,"
                 " after %.1f s in the queue",
                 row["instance_id"], row["vantage"], outcome, held,
                 _waited(row["submitted_at"], start))
        return outcome
    finally:
        stripes.release()


def our_pass_runs(con: sqlite3.Connection) -> bool:
    """Whether a pass of ours is running from this box, which the worker
    steps aside for (see the top)."""
    return probelock.is_held(probelock.ours_path_for(con))


def still_its_row(con: sqlite3.Connection, vantage) -> bool:
    """Whether the registry still has this prober under this row. A prober
    taken out and added again is another row with another lock."""
    current = vantages.by_name(con, vantage.name)
    return current is not None and current.id == vantage.id


def run_prober_round(con: sqlite3.Connection, vantage, *,
                     transport_factory=dispatch.SshTransport,
                     lock_wait_seconds: float = probelock.WAIT_SECONDS,
                     hold_seconds: float | None = None, clock=time.monotonic,
                     now=_now, keep_going=lambda: True,
                     sleep=time.sleep) -> list:
    """Take one prober's lock, run its queued batches for up to
    `hold_seconds`, let it go. Returns the outcomes, empty when nothing was
    queued for it or nothing could start.

    `vantage` is the prober's row in the registry, and its lock is keyed on
    the row's id. The lock is only asked for when something is queued for
    this prober, so an idle thread never makes one of our own passes wait.
    `keep_going` is asked between batches and while the lock is waited
    for, and is how a stop lets the running batch finish. `sleep` is how the
    wait for the lock sleeps between polls. `hold_seconds` None is
    `HOLD_SECONDS`, read when the round starts. While a pass of ours runs,
    or once this prober is another row of the registry, no batch starts.
    """
    hold = HOLD_SECONDS if hold_seconds is None else hold_seconds
    proberapi.sweep(con, now())
    if proberapi.next_queued(con, now(), vantage=vantage.name) is None:
        return []
    if our_pass_runs(con):
        return []
    outcomes = []
    passed_over = set()
    with probelock.Locks(probelock.directory_for(con), prober=vantage.id,
                         wait_seconds=lock_wait_seconds, sleep=sleep,
                         keep_going=keep_going):
        started = clock()
        while clock() - started < hold and keep_going():
            if our_pass_runs(con) or not still_its_row(con, vantage):
                break
            row = proberapi.next_queued(con, now(), vantage=vantage.name,
                                        skip=passed_over)
            if row is None:
                break
            outcome = _start_and_run(con, row, vantage, transport_factory,
                                     clock, now)
            if outcome is None:
                passed_over.add(row["id"])
                continue
            outcomes.append(outcome)
    return outcomes


def close_unserved(con: sqlite3.Connection, now: datetime) -> list:
    """Close as `vantage_unreachable` every queued batch whose vantage was
    taken out of the registry after it was queued, since no thread serves a
    row that is gone. Nothing is sent. Returns their outcomes."""
    outcomes = []
    names = {v.name for v in vantages.list_all(con)}
    for row in proberapi.queued_for_others(con, names, now):
        if vantages.by_name(con, row["vantage"]) is not None:
            continue
        proberapi.record_failure(con, row, "vantage_unreachable", now)
        outcomes.append("vantage_unreachable")
    return outcomes


def run_round(con: sqlite3.Connection, *, transport_factory=dispatch.SshTransport,
              lock_wait_seconds: float = probelock.WAIT_SECONDS,
              hold_seconds: float | None = None, clock=time.monotonic,
              now=_now, keep_going=lambda: True) -> list:
    """One round of every prober in the registry, one after another, in this
    thread: what `--once` runs. The unit runs a thread per prober instead
    (`serve`). Returns the outcomes, empty when nothing was queued."""
    outcomes = close_unserved(con, now())
    for vantage in vantages.list_all(con):
        outcomes.extend(run_prober_round(
            con, vantage, transport_factory=transport_factory,
            lock_wait_seconds=lock_wait_seconds, hold_seconds=hold_seconds,
            clock=clock, now=now, keep_going=keep_going))
    return outcomes


def _serve_prober(path: str, vantage, stop: threading.Event,
                  transport_factory, broken: threading.Event) -> None:
    """One prober's thread: rounds until `stop` is set, on a connection of
    its own. Waiting is done on the event, between rounds and while the
    prober's lock is waited for, so a stop is noticed within a poll. It ends
    by itself when its prober is no longer this row of the registry, and an
    error of no known kind sets `broken` and `stop`, which ends the worker
    (see the top)."""
    con = db.connect(path)
    try:
        while not stop.is_set():
            try:
                if not still_its_row(con, vantage):
                    log.warning("%s: no longer row %s of the registry, so its"
                                " thread ends", vantage.name, vantage.id)
                    return
                queued = proberapi.next_queued(con, _now(),
                                               vantage=vantage.name) is not None
                run_prober_round(con, vantage, transport_factory=transport_factory,
                                 keep_going=lambda: not stop.is_set(),
                                 sleep=stop.wait)
            except probelock.ProbeLockHeld as exc:
                if stop.is_set():
                    break
                # The prober was busy for the whole wait. Nothing was sent,
                # the batches stay queued, and the next round tries again.
                # One typed line, as a pass of ours writes for each batch.
                log.warning("%s", probelock.held_line(exc, vantage.name, None))
                continue
            except sqlite3.OperationalError as exc:
                # "database is locked" past the busy timeout, say. One round
                # is lost, never the thread. The refused write leaves the
                # transaction Python opened for it open, and the next round
                # would read inside it and keep that old snapshot for good:
                # every later write refused and no checkpoint past it, so the
                # -wal file grows. Ended here, so the next round starts clean.
                con.rollback()
                log.warning("%s: the database refused this round, %s,"
                            " and the next one starts in %g s", vantage.name,
                            type(exc).__name__, IDLE_POLL_SECONDS)
                stop.wait(IDLE_POLL_SECONDS)
                continue
            stop.wait(YIELD_SECONDS if queued else IDLE_POLL_SECONDS)
    except Exception as exc:
        log.error("%s: its thread met %s, so the worker ends, and systemd"
                  " starts it again and closes the batch it had claimed",
                  vantage.name, type(exc).__name__)
        broken.set()
        stop.set()
    finally:
        con.close()


def serve(con: sqlite3.Connection, *, stop: threading.Event | None = None,
          transport_factory=dispatch.SshTransport) -> int:
    """The unit's mode: a thread per prober in the registry until `stop` is
    set. Returns the exit code: 0 for a stop, 1 when a thread met an error of
    no known kind, so systemd starts the worker again, and
    `probelock.EXIT_HELD` when another worker holds the life lock, and then
    nothing at all was done.

    A prober added to the registry while it runs gets its thread within a
    second. A batch queued for a prober taken out of it is closed."""
    stop = stop or threading.Event()
    life = WorkerLock.for_connection(con)
    if not life.try_acquire():
        log.warning("another worker holds %s, so this one exits and closes"
                    " nothing", life.path)
        return probelock.EXIT_HELD
    try:
        closed = proberapi.fail_interrupted(con, _now())
        if closed:
            log.warning("%d batches were cut off by the last stop and are"
                        " closed as interrupted", closed)
        path = _database_file(con)
        if path is None:
            raise ValueError("the worker needs a database on disk, which its"
                             " threads open each for themselves")
        broken = threading.Event()
        threads = {}
        while not stop.is_set():
            try:
                for vantage in vantages.list_all(con):
                    key = (vantage.id, vantage.name)
                    if key not in threads:
                        thread = threading.Thread(
                            target=_serve_prober, name=f"prober-{vantage.id}",
                            args=(path, vantage, stop, transport_factory, broken))
                        thread.start()
                        threads[key] = thread
                close_unserved(con, _now())
            except sqlite3.OperationalError as exc:
                # Ended for the same reason as in a prober's thread.
                con.rollback()
                log.warning("the database refused the worker's look at the"
                            " registry, %s", type(exc).__name__)
            # A thread that ended while the worker runs had its prober leave
            # the registry, and is forgotten. One that broke stopped the
            # worker, and the loop ends.
            for key, thread in list(threads.items()):
                if not thread.is_alive():
                    del threads[key]
            stop.wait(IDLE_POLL_SECONDS)
        for thread in threads.values():
            thread.join()
        return 1 if broken.is_set() else 0
    finally:
        life.release()


def _database_file(con: sqlite3.Connection) -> str | None:
    """The file of the database `con` is open on, None for one in memory."""
    for row in con.execute("PRAGMA database_list"):
        if row[1] == "main":
            return row[2] or None
    return None


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="proberapi_worker", description=__doc__.split("\n`app/")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--once", action="store_true",
                        help="run one round of queued batches, then exit")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        con = cli.open_database(args)
    except sqlite3.Error as exc:
        print(f"the database could not be used: {exc}", file=sys.stderr)
        return 1
    try:
        db.init(con)
        authz.init(con)
        prober.init(con)
        vantages.init(con)
        instances.init(con)
        proberapi.init(con)
        if args.once:
            life = WorkerLock.for_connection(con)
            if not life.try_acquire():
                print(f"another worker holds {life.path}, so nothing was run",
                      file=sys.stderr)
                return probelock.EXIT_HELD
            try:
                outcomes = run_round(con)
            except probelock.ProbeLockHeld as exc:
                print(exc, file=sys.stderr)
                return probelock.EXIT_HELD
            finally:
                life.release()
            print(f"{len(outcomes)} batches: {', '.join(outcomes) or 'none queued'}")
            return 0
        stop = threading.Event()
        # What `systemctl stop` and `restart` send. The batch each thread is
        # running finishes, then the threads end.
        signal.signal(signal.SIGTERM, lambda signum, frame: stop.set())
        return serve(con, stop=stop)
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
