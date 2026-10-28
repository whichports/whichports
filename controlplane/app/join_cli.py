"""Show the findings: what each view said about a port, and which layer decided.

    python -m app.join_cli findings              # every host, what needs a person
    python -m app.join_cli findings --all        # every port, every family
    python -m app.join_cli findings --host box1

## Why this exists

`app/join.py` produces the answer this product is for, and until this command
nothing showed it to anybody. The renderer does not read findings yet, and
outside the tests the only caller of `fleet_findings` was `intent_cli`, which
reads a state to attach an acknowledgement to it. So the central output of the
product could not be looked at.

## What it will not do

  - **It never invents a state.** `join._decide` is the only thing that names
    one, and where it declines to, this command prints the two views and leaves
    the state column empty. Deciding what a case earns is the engine's, and
    filling a gap in a formatter would be taking that decision somewhere nobody
    would think to look for it.
  - **It never says reachable.** It reports what each view observed, in the
    engine's own words and the prober's own words, and stops. The writing rules
    own that, and a test here holds this file to it separately from
    the one that holds `join.describe` to it.
  - **It names the vantage.** A connect result without the place it was
    attempted from is half a fact (`docs/PRODUCT.md` 5e), so the listing says
    where and when, or says the host has never been probed.

## The default is not everything

A listing that prints every port on both families for every host is the wall of
text the owner rejected in `docs/RECORD.md` 4.49. The default shows the rows that
want a person: anything with a state other than `intended`, anything the
outside view actually measured, and anything acknowledged. `--all` prints the
rest, including every `not tested` row, because sometimes the question is what
was not measured.
"""

import argparse
import sqlite3
import sys

from . import cli, db, join

# Column width for the state, wide enough for the longest of the five words so
# the listing lines up without a table library.
_STATE_WIDTH = max(len(state) for state in join.STATES)


def _worth_showing(finding) -> bool:
    """Whether the default listing includes this row.

    `intended` means reality and the declaration agree, which is the one case
    nobody has to read. Everything else either has a state that says something
    or carries a measurement, and a row with neither is noise until somebody
    asks for it with --all.
    """
    if finding.acknowledged:
        return True
    if finding.state == join.STATE_INTENDED:
        # Measured, declared, and they agree. This is the row the default
        # exists to leave out, and leaving it in defeated the filter: on a
        # healthy fleet almost every measured row is this one.
        return False
    if finding.state:
        return True
    return bool(finding.outside.measured)


def _finding_line(finding) -> str:
    where = f"{finding.protocol}/{finding.port}"
    state = finding.state or ""
    outside = finding.outside.state or "not tested"
    line = f"  {where:<12} {finding.family:<3} {state:<{_STATE_WIDTH}}  outside {outside}"
    if finding.intent:
        line += f"  declared {finding.intent}"
    if finding.acknowledged:
        line += "  acknowledged"
    return line


def _host_header(host_findings) -> str:
    """The host, and the clock on its outside view.

    A listing that shows connect results without saying when and from where
    invites somebody to act on a week old answer taken from a network that no
    longer exists.

    The clock is read off the findings rather than off a single run, because
    the engine no longer has one run behind a host: it reads the newest
    measurement per port across every run. The most recently measured port names
    the time and vantage here, which is the same newest-measurement rule the
    site's probe-source line follows.
    """
    parts = [host_findings.host_name]
    if host_findings.paused:
        parts.append("(paused)")
    if not host_findings.document_readable:
        parts.append("(its document could not be read)")
    measured = [f for f in host_findings.findings if f.outside.measured]
    if not measured:
        parts.append("never probed, so every outside view is not tested")
    else:
        newest = max(measured, key=lambda f: f.outside.measured_at or "")
        parts.append(f"probed {newest.outside.measured_at} "
                     f"from {newest.outside.vantage or 'an unnamed vantage'}")
    return " ".join(parts)


def _print_host(host_findings, show_all: bool) -> int:
    rows = [f for f in host_findings.findings if show_all or _worth_showing(f)]
    print()
    print(_host_header(host_findings))
    if not rows:
        print("  nothing that wants a person, and --all shows the rest")
        return 0
    for finding in rows:
        print(_finding_line(finding))
        if finding.cause and finding.cause.layer:
            print(f"        decided at: {finding.cause.layer}")
            for quote in (finding.cause.quotes or [])[:3]:
                print(f"        {quote.source}: {quote.text}")
    return len(rows)


def run(con: sqlite3.Connection, args) -> int:
    """The command itself, with the connection passed in so the tests drive it
    against a temporary database."""
    if args.command != "findings":
        return 1
    show_all = bool(getattr(args, "all", False))
    wanted = getattr(args, "host", None)

    # Revoking is the operator saying this row is not a server of mine, which
    # is the same reason the fleet view drops them (RECORD 4.51).
    everything = [h for h in join.fleet_findings(con) if not h.revoked_at]
    if wanted is not None:
        everything = [h for h in everything if h.host_name == wanted]
        if not everything:
            print(f"no host named {wanted!r} that we still accept reports from",
                  file=sys.stderr)
            return 1
    if not everything:
        print("no hosts enrolled")
        return 0

    shown = 0
    for host_findings in everything:
        shown += _print_host(host_findings, show_all)
    print()
    print(f"{len(everything)} hosts, {shown} findings shown"
          + ("" if show_all else ", --all shows every port and family"))
    return 0


def parse_args(argv=None):
    usage = __doc__.split("\n## ")[0]
    parser = argparse.ArgumentParser(
        prog="findings", description=usage,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("findings", help="what each view said, per port")
    p.add_argument("--host", help="one host by name, rather than all of them")
    p.add_argument("--all", action="store_true",
                   help="every port and both families, including the ones"
                        " nothing measured")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    con = cli.open_database(args)
    try:
        db.init(con)
        return run(con, args)
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
