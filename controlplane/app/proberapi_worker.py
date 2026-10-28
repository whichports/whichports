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

## One batch at a time, under the pass lock

Every batch runs while this process holds `probe.lock`
(`app/probelock.py`), the lock every probing pass on this box holds. So a
batch never runs beside one of our own timers' passes or another instance's
batch, and a target never has two of our runners against it, whichever
instances asked and whichever vantages they named (`docs/PRODUCT.md` 5d).

The lock is held for at most `HOLD_SECONDS` of batches and then let go for
`YIELD_SECONDS`, because flock(2) is not fair: a process that lets go and
takes it again at once can keep a waiting timer out for as long as the queue
is full. A pass waiting on it asks again every `probelock.POLL_SECONDS`, so a
pause of twice that is always long enough for it to get in.

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
import json
import logging
import signal
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone

from . import (authz, cli, db, dispatch, instances, probelock, prober,
               proberapi, vantages)

log = logging.getLogger(__name__)

# How long the lock is held for one round of batches before it is let go.
HOLD_SECONDS = 30.0

# How long it is let go for. Twice a waiting pass's poll, so it gets in.
YIELD_SECONDS = 2 * probelock.POLL_SECONDS

# How often an empty queue is asked again. The instance polls its answer
# every second, so a second here keeps the wait it sees to about two.
IDLE_POLL_SECONDS = 1.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


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


def run_batch(con: sqlite3.Connection, row, transport_factory,
              now: datetime) -> str:
    """Run one claimed batch and record what came of it. Returns the outcome,
    `done`, `dropped` or a failure class, for the journal and the tests."""
    instance = instances.by_id(con, row["instance_id"])
    if instance is None or instance.revoked_at:
        # Revoked after it queued. Nothing is sent, and nobody can collect
        # it, because the key that would is refused.
        proberapi.drop(con, row)
        return "dropped"

    request = proberapi.BatchRequest.from_json(row["request"])
    vantage = vantages.by_name(con, request.vantage)
    if vantage is None or not vantage.enabled:
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

    allowed = _allowed(request)
    # `dispatch.build_batch` is the one owner of the batch's shape and the
    # one place a snapshot is read for a batch, so it builds this one too,
    # under the instance's account and for the allowed addresses only. Then
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


def run_round(con: sqlite3.Connection, *, transport_factory=dispatch.SshTransport,
              lock_wait_seconds: float = probelock.WAIT_SECONDS,
              hold_seconds: float = HOLD_SECONDS, clock=time.monotonic,
              now=_now, keep_going=lambda: True) -> list:
    """Take the pass lock, run queued batches for up to `hold_seconds`, let it
    go. Returns the outcomes, empty when nothing was queued.

    The lock is only asked for when something is queued, so an idle worker
    never makes one of our own passes wait. `keep_going` is asked between
    batches, and is how a stop lets the running batch finish.
    """
    proberapi.sweep(con, now())
    if proberapi.next_queued(con, now()) is None:
        return []
    outcomes = []
    with probelock.ProbeLock.for_connection(con, wait_seconds=lock_wait_seconds):
        started = clock()
        while clock() - started < hold_seconds and keep_going():
            row = proberapi.next_queued(con, now())
            if row is None:
                break
            if not proberapi.mark_started(con, row["id"], now()):
                continue
            began = clock()
            outcome = run_batch(con, row, transport_factory, now())
            # The time each batch took, in the journal, because what one batch
            # costs is what decides how many instances one lock can carry, and
            # it is measured on the box rather than guessed (RUNBOOK).
            log.info("batch for instance %s from %s: %s in %.1f s",
                     row["instance_id"], row["vantage"], outcome, clock() - began)
            outcomes.append(outcome)
    return outcomes


def serve(con: sqlite3.Connection, *, stop: threading.Event | None = None,
          rounds=None) -> None:
    """The unit's mode: rounds until `stop` is set. `rounds` bounds it for a
    test. Waiting is done on the event, so a stop is noticed at once rather
    than after the sleep."""
    stop = stop or threading.Event()
    closed = proberapi.fail_interrupted(con, _now())
    if closed:
        log.warning("%d batches were cut off by the last stop and are closed"
                    " as interrupted", closed)
    done = 0
    while not stop.is_set() and (rounds is None or done < rounds):
        done += 1
        try:
            outcomes = run_round(con, keep_going=lambda: not stop.is_set())
        except probelock.ProbeLockHeld as exc:
            # A pass held the lock for the whole wait. Nothing was sent, the
            # batches stay queued, and the next round tries again.
            log.warning("%s", exc)
            continue
        stop.wait(YIELD_SECONDS if outcomes else IDLE_POLL_SECONDS)


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
            try:
                outcomes = run_round(con)
            except probelock.ProbeLockHeld as exc:
                print(exc, file=sys.stderr)
                return probelock.EXIT_HELD
            print(f"{len(outcomes)} batches: {', '.join(outcomes) or 'none queued'}")
            return 0
        stop = threading.Event()
        # What `systemctl stop` and `restart` send. The batch that is running
        # finishes, then the loop ends.
        signal.signal(signal.SIGTERM, lambda signum, frame: stop.set())
        serve(con, stop=stop)
        return 0
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
