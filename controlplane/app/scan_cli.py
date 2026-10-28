"""Respond to on-demand scan requests: probe every host that asked, from the
vantage host, and clear the requests once they are handled.

    python -m app.scan_cli drain --registry --tls-known
    python -m app.scan_cli drain --vantage probe1 --via root@198.51.100.7

whichports-scan.path starts the unit that runs this whenever the ingest writes
the trigger file (app/scan.py). It reads the pending requests, and for each host
still accepted it probes the same joined port set the fast lane does, from the
same vantage hosts, over the same ssh transport (app/dispatch.py). Probing
happens there and never on the ingest box, which has no channel to the vantage
host and must never get one.

`--registry` drives every enabled vantage in `app/vantages.py`, one after
another, the way `prober_cli probe --registry` does, and it is what the unit
passes since 2026-09-08. The older `--vantage` and `--via` pair names one
vantage by hand, a vantage of the registry and its destination since the
finer locks (`prober_cli.registry_row_for_via`).

**With more than one vantage, a request is cleared once any vantage measured
the host.** The person asked for an outside answer now and got one. A vantage
that failed is reported, and its own view catches up on the next lane pass
rather than holding the request open, because a dead vantage would otherwise
keep every request pending until it came back.

## What it clears, and what it deliberately leaves

A host that was measured, or that can never be probed now (revoked, or with
nothing derived from any document), has its requests cleared so a later drain
does not probe for them again.

**A host whose pass failed keeps its request.** A `DispatchFailed` means the
pass did not happen, the same as an unreachable vantage host, so the request
stays pending and the next drain retries it. Clearing it would turn a pass that
did not happen into one that found nothing, which is the shape docs/RECORD.md
4.46 keeps finding. There is no busy loop: a drain runs only when the trigger
fires or the fast lane runs, never on a timer of its own.
"""

import argparse
import contextlib
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone

from . import (authz, cli, db, dispatch, probelock, prober, prober_cli, scan,
               store, vantages)


def _drain(con: sqlite3.Connection, args) -> int:
    registry = getattr(args, "registry", False)
    vantage = via = None
    chosen = []
    if registry:
        chosen = vantages.enabled(con)
        if not chosen:
            print("no enabled vantage in the registry, so nothing is probed."
                  " Add one with python -m app.vantages_cli add",
                  file=sys.stderr)
            return 2
    else:
        vantage, complaint = prober_cli.chosen_vantage(args)
        if vantage is None:
            print(complaint, file=sys.stderr)
            return 2
        via = getattr(args, "via", None)
        if not via:
            print("a drain probes from a vantage host over ssh, so --via"
                  " user@address or --registry is required", file=sys.stderr)
            return 2
        via_row, complaint = prober_cli.registry_row_for_via(con, vantage, via)
        if via_row is None:
            print(complaint, file=sys.stderr)
            return 2

    host_ids = scan.pending_requests(con)
    if not host_ids:
        print("no scan requests are waiting")
        return 0

    exclude = prober_cli._vantage_addresses(con)
    # The same certificate reads the fast lane makes, so a scan somebody asked
    # for answers the same questions a timer's pass answers.
    tls_ports = prober_cli.tls_ports_for((), getattr(args, "tls_known", False))
    # A registry drain uses ssh, or our prober API on a self-hosted instance
    # (dispatch.default_transport_factory). A drain `--via` names an ssh
    # destination, so it is ssh whatever the environment says.
    factory = getattr(args, "transport_factory", None)
    if factory is None:
        try:
            factory = (dispatch.default_transport_factory() if registry
                       else dispatch.SshTransport)
        except dispatch.TransportConfigError as exc:
            print(exc, file=sys.stderr)
            return 2
    transport = None if registry else factory(via)
    now = datetime.now(timezone.utc)
    tally: Counter = Counter()
    failed = []
    deleted = []
    measured = 0
    # The locks, app/probelock.py, the same as a timer's pass takes: a drain
    # landing on top of one is exactly the overlap they exist to stop. The
    # drain holds probe.ours for the page's mark, and on a self-hosted
    # instance probe.lock whole around the loop, one pass at a time
    # (dispatch.uses_prober_api). On our box each batch takes its prober's
    # lock and its addresses', so a Scan now runs beside a timer's pass.
    wait = getattr(args, "lock_wait_seconds", probelock.WAIT_SECONDS)
    locks = probelock.BatchLocks.for_connection(con, wait_seconds=wait)
    held = contextlib.ExitStack()
    held.enter_context(probelock.OurPass.for_connection(con))
    if dispatch.uses_prober_api():
        locks = None
        try:
            held.enter_context(probelock.ProbeLock.for_connection(
                con, wait_seconds=wait))
        except probelock.ProbeLockHeld as exc:
            held.close()
            print(exc, file=sys.stderr)
            return probelock.EXIT_HELD
    via_locks = None if locks is None or registry else locks.on_prober(via_row.id)
    try:
        for host_id in host_ids:
            request_ids = scan.pending_ids_for_host(con, host_id)
            host = store.host_by_id(con, host_id)
            if host is None or host["revoked_at"]:
                # Revoked or gone: nothing is probed and the request is cleared, so
                # it does not sit pending forever.
                name = host["name"] if host is not None else f"host {host_id}"
                print(f"{name}: revoked, so nothing is probed and the request is"
                      " cleared")
                scan.mark_drained(con, request_ids, now)
                continue

            plan = prober_cli._with_joined_ports(con, prober_cli.plan_for(con, host))
            if not plan.derived:
                # Never reported, or an unreadable document: there is nothing to
                # derive a target from, so there is nothing to probe. Cleared rather
                # than retried, because a fresh scan after the host reports records a
                # new request.
                print(f"{plan.name}: {plan.note}")
                scan.mark_drained(con, request_ids, now)
                continue

            if registry:
                outcomes = dispatch.run_pass(con, [plan], chosen,
                                             transport_factory=factory,
                                             exclude=exclude, tls_ports=tls_ports,
                                             locks=locks)
            else:
                outcomes = _one_vantage(con, plan, transport, vantage, exclude,
                                        tls_ports, locks=via_locks)
            any_measured = False
            for outcome in outcomes:
                print()
                print(f"{plan.name} from {outcome.vantage}")
                if outcome.gone:
                    # Deleted after its scan was asked for and while it was
                    # measured. Its request went with it, so nothing is left
                    # pending, and it is no failure of the drain.
                    print(f"  not measured: {outcome.failure}")
                    deleted.append(plan.name)
                    continue
                if outcome.run is None:
                    # Typed, printed, never a finding. A pass that did not happen
                    # must not read like a pass that found nothing.
                    print(f"  not measured: {outcome.failure}", file=sys.stderr)
                    failed.append(f"{plan.name} from {outcome.vantage}")
                    continue
                any_measured = True
                prober_cli._print_results(outcome.run.results)
                prober_cli._print_certificates(outcome.run.certificates)
                for row in outcome.run.results:
                    tally[row.state] += 1
                print(f"  run {outcome.run.id} stored from {outcome.run.vantage},"
                      f" {len(outcome.run.results)} results")
            if not any_measured:
                # Left pending, so the next drain retries it rather than turning a
                # pass that did not happen into one that found nothing.
                continue
            scan.mark_drained(con, request_ids, now)
            measured += 1

    finally:
        held.close()

    print()
    where = (", ".join(v.name for v in chosen) if registry
             else f"{vantage} via {via}")
    print(f"{measured} of {len(host_ids)} requested hosts measured from {where}")
    for state, count in sorted(tally.items()):
        print(f"  {state}: {count}")
    prober_cli._print_deleted(deleted)
    if failed:
        print(f"  not measured: {', '.join(failed)}")
        return 1
    return 0


def _one_vantage(con, plan, transport, vantage, exclude, tls_ports=(),
                 locks=None) -> list:
    """The hand-named path, as one outcome, so the printing above has one
    shape whichever way the vantage was chosen."""
    try:
        run = dispatch.run_host(con, plan, transport, vantage, exclude=exclude,
                                tls_ports=tls_ports, locks=locks)
    except dispatch.DispatchFailed as exc:
        return [dispatch.Outcome(plan.name, vantage, failure=str(exc))]
    except prober.HostGone:
        return [dispatch.Outcome(plan.name, vantage,
                                 failure=dispatch.SERVER_DELETED, gone=True)]
    return [dispatch.Outcome(plan.name, vantage, run=run)]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="scan", description=__doc__.split("\n## ")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p_drain = sub.add_parser(
        "drain",
        help="probe every host that asked for a scan, from the vantage host")
    p_drain.add_argument("--vantage", metavar="NAME",
                         help="where this run is being taken from, stored with"
                              " every result. " + prober.VANTAGE_ENV + " sets it"
                              " too, and this flag wins when both are set")
    p_drain.add_argument("--via", metavar="DESTINATION",
                         help="probe from a vantage host over ssh, as"
                              " user@address, the destination of the vantage"
                              " --vantage names in the registry. The packets"
                              " leave that machine and never this one")
    p_drain.add_argument("--registry", action="store_true",
                         help="probe from every enabled vantage in the"
                              " registry, one after another. This is what the"
                              " unit passes")
    p_drain.add_argument("--tls-known", action="store_true",
                         help="read the certificate on the known TLS ports the"
                              " plan carries, as the timers do")
    return parser.parse_args(argv)


def run(con: sqlite3.Connection, args) -> int:
    if args.command == "drain":
        return _drain(con, args)
    return 1


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        con = cli.open_database(args)
    except sqlite3.Error as exc:
        print(f"the database could not be used: {exc}", file=sys.stderr)
        return 1
    try:
        # Additive and idempotent, the same as the other commands. authz and
        # prober are needed because the drain builds a snapshot and stores a run
        # through the paths dispatch.run_host uses.
        db.init(con)
        authz.init(con)
        prober.init(con)
        scan.init(con)
        vantages.init(con)
        return run(con, args)
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
