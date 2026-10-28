"""Say where the outside view is taken from, from the terminal.

    python -m app.vantages_cli list
    python -m app.vantages_cli add --name probe1 --via root@78.141.210.130 \
        --address 78.141.210.130 --address 2a05:f480:1400:2015:5400:6ff:fe94:df5
    python -m app.vantages_cli off --name probe2
    python -m app.vantages_cli on --name probe2
    python -m app.vantages_cli set-via --name probe2 --via root@203.0.113.9
    python -m app.vantages_cli set-addresses --name probe2 --address 203.0.113.9
    python -m app.vantages_cli remove --name probe2
    python -m app.vantages_cli sync-api        # a self-hosted instance

`app/vantages.py` owns the storage and the reasoning. The one thing worth
repeating here: **an address goes on the published list in `site/probers.py`,
and that list is deployed, before it is added here.** `ops/RUNBOOK.md` "The
ordering rule" says why. This command cannot check that for you, because the
published list is built by another program.

`--via` is an ssh destination and never a credential. The key is found by
`ssh` itself through `~/.ssh/config` on the control plane.

**`sync-api` is for a self-hosted instance**, which drives no box of its own
and uses ours through the prober API (`dispatch.ApiTransport`). It makes this
registry exactly the vantages the API lists, each row's destination being the
vantage's own name, and every address kept so none is ever a target. It reads
`WHICHPORTS_PROBER_API` and `WHICHPORTS_PROBER_API_KEY` from the environment
file, the same two settings a pass reads.
"""

import argparse
import os
import sqlite3
import sys

from . import cli, dispatch, vantages


def _print_list(con) -> int:
    found = vantages.list_all(con)
    if not found:
        print("no vantages. Nothing probes from anywhere.")
        print("add one with: python -m app.vantages_cli add --name NAME"
              " --via user@host --address ADDRESS")
        return 0
    for vantage in found:
        print(f"  {vantage.name}")
        print(f"    state      {'on' if vantage.enabled else 'off'}")
        print(f"    via        {vantage.destination}")
        for address in vantage.addresses:
            print(f"    address    {address}")
        print(f"    added      {vantage.added_at}")
    return 0


def _sync_api(con, environ=None, opener=None) -> int:
    environ = os.environ if environ is None else environ
    base_url = environ.get(dispatch.PROBER_API_ENV, "").strip()
    key = environ.get(dispatch.PROBER_API_KEY_ENV, "").strip()
    if not base_url or not key:
        print(f"sync-api needs {dispatch.PROBER_API_ENV} and"
              f" {dispatch.PROBER_API_KEY_ENV}, and this environment has"
              f" {'neither' if not (base_url or key) else 'only one'}",
              file=sys.stderr)
        return 2
    try:
        listed = dispatch.fetch_api_vantages(base_url, key, opener=opener)
    except dispatch.DispatchFailed as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except dispatch.TransportConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    changes = vantages.sync_from_api(con, listed)
    for change in changes:
        print(change)
    print(f"{len(listed)} vantages from the prober API"
          f"{'' if changes else ', nothing changed'}")
    return 0


def run(con, args) -> int:
    try:
        if args.command == "list":
            return _print_list(con)
        if args.command == "add":
            vantage = vantages.add(con, args.name, args.via, args.addresses)
            print(f"added {vantage.name}, via {vantage.destination},"
                  f" {len(vantage.addresses)} addresses, on")
            return 0
        if args.command == "remove":
            vantages.remove(con, args.name)
            print(f"removed {args.name}")
            return 0
        if args.command in ("on", "off"):
            vantages.set_enabled(con, args.name, args.command == "on")
            print(f"{args.name} is {args.command}")
            return 0
        if args.command == "set-via":
            vantages.set_destination(con, args.name, args.via)
            print(f"{args.name} via {args.via}")
            return 0
        if args.command == "sync-api":
            return _sync_api(con)
        if args.command == "set-addresses":
            vantages.set_addresses(con, args.name, args.addresses)
            print(f"{args.name} has {len(args.addresses)} addresses")
            return 0
    except vantages.VantageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 1


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="vantages", description=__doc__.split("\n`app/")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="every vantage, on or off, with its addresses")

    p_add = sub.add_parser("add", help="add a vantage, enabled")
    p_add.add_argument("--name", required=True, metavar="NAME")
    p_add.add_argument("--via", required=True, metavar="DESTINATION",
                       help="ssh destination, user@host. Never a credential")
    p_add.add_argument("--address", required=True, action="append",
                       dest="addresses", metavar="ADDRESS",
                       help="an address this vantage probes from. Repeatable,"
                            " one per family. Publish it first")

    for name, help_text in (("remove", "take a vantage out of the registry"),
                            ("on", "drive this vantage on every pass"),
                            ("off", "stop driving this vantage")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--name", required=True, metavar="NAME")

    p_via = sub.add_parser("set-via", help="change where ssh reaches a vantage")
    p_via.add_argument("--name", required=True, metavar="NAME")
    p_via.add_argument("--via", required=True, metavar="DESTINATION")

    sub.add_parser("sync-api",
                   help="a self-hosted instance: take the vantages our prober"
                        " API lists")

    p_addr = sub.add_parser("set-addresses",
                            help="replace a vantage's addresses after a rebuild")
    p_addr.add_argument("--name", required=True, metavar="NAME")
    p_addr.add_argument("--address", required=True, action="append",
                        dest="addresses", metavar="ADDRESS")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        con = cli.open_database(args)
    except sqlite3.Error as exc:
        print(f"the database could not be used: {exc}", file=sys.stderr)
        return 1
    try:
        vantages.init(con)
        return run(con, args)
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
