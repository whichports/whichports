"""Stop a server or a port from mailing, from the terminal.

    python -m app.silence_cli mute app-01
    python -m app.silence_cli mute app-01 --hours 8
    python -m app.silence_cli unmute app-01
    python -m app.silence_cli silence app-01 tcp 2019 v4
    python -m app.silence_cli unsilence app-01 tcp 2019 v4
    python -m app.silence_cli list

`docs/PRODUCT.md` 4c asks for two controls and this is both of them. **Mute**
is while you work: per server, two hours by default, and the changes are still
recorded and still shown, they just do not mail. **Silence** is permanent and
per port, for the port you have already decided about and do not want asked
again, and 4c asks for it without an argument from a settings page.

Neither of them touches the dead-man switch. A server that goes quiet still
raises, because that alert is about the agent rather than about a finding, and
`store.pause_host` is the control for it.

`--workspace` decides whose servers these commands can name, and it defaults
to 1, so nothing run today changes. A server in another workspace is refused
in the same words a name nobody enrolled gets.
"""

import argparse
import sys

from . import alerts, cli, db, finding_alerts, intent, prober


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="silence", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def workspace_argument(command) -> None:
        command.add_argument("--workspace", type=int,
                             default=db.DEFAULT_WORKSPACE_ID,
                             help="which workspace to work in"
                                  f" (default {db.DEFAULT_WORKSPACE_ID})")

    def port_arguments(command) -> None:
        command.add_argument("host")
        command.add_argument("protocol", choices=sorted(intent.PROTOCOLS))
        command.add_argument("port", type=int)
        command.add_argument("family", choices=sorted(intent.FAMILIES))
        workspace_argument(command)

    p_mute = sub.add_parser("mute", help="stop this server mailing for a while")
    p_mute.add_argument("host")
    p_mute.add_argument("--hours", type=float,
                        default=finding_alerts.DEFAULT_MUTE_SECONDS / 3600,
                        help="how long, in hours. Two by default")
    workspace_argument(p_mute)

    p_unmute = sub.add_parser("unmute", help="let this server mail again")
    p_unmute.add_argument("host")
    workspace_argument(p_unmute)

    p_silence = sub.add_parser(
        "silence", help="never mail about this port on this family again")
    port_arguments(p_silence)

    p_unsilence = sub.add_parser("unsilence", help="lift a permanent silence")
    port_arguments(p_unsilence)

    p_list = sub.add_parser("list", help="every mute and silence that is live now")
    workspace_argument(p_list)

    return parser.parse_args(argv)


def run(con, args) -> int:
    try:
        if args.command == "mute":
            # The seconds rather than the hours, because a positive number of
            # hours can still round down to no time at all. `--hours 0.0001`
            # used to store a mute that had already expired, and the store now
            # refuses one, which would have been a traceback here.
            seconds = int(args.hours * 3600)
            if seconds <= 0:
                print("a mute needs a positive number of hours", file=sys.stderr)
                return 1
            finding_alerts.mute_host(con, args.host, seconds=seconds,
                                     workspace_id=args.workspace)
            print(f"{args.host} will not mail for {args.hours:g} hours. "
                  "Changes are still recorded")
            return 0

        if args.command == "unmute":
            if finding_alerts.unmute_host(con, args.host,
                                          workspace_id=args.workspace):
                print(f"{args.host} can mail again")
                return 0
            print(f"{args.host} was not muted", file=sys.stderr)
            return 1

        if args.command == "silence":
            finding_alerts.silence_port(con, args.host, args.protocol,
                                        args.port, args.family,
                                        workspace_id=args.workspace)
            print(f"{args.host} {args.protocol}/{args.port} on {args.family} "
                  "will not mail again")
            return 0

        if args.command == "unsilence":
            if finding_alerts.unsilence_port(con, args.host, args.protocol,
                                             args.port, args.family,
                                             workspace_id=args.workspace):
                print(f"{args.host} {args.protocol}/{args.port} on "
                      f"{args.family} can mail again")
                return 0
            print(f"{args.host} {args.protocol}/{args.port} on {args.family} "
                  "was not silenced", file=sys.stderr)
            return 1

        if args.command == "list":
            return _print_live(con, args.workspace)
    except intent.IntentError as exc:
        print(f"cannot do that: {exc}", file=sys.stderr)
        return 1
    return 1


def _print_live(con, workspace_id=db.DEFAULT_WORKSPACE_ID) -> int:
    rows = finding_alerts.list_silences(con, workspace_id=workspace_id)
    if not rows:
        print("nothing is muted or silenced")
        return 0
    names = {row["id"]: row["name"] for row in con.execute(
        "SELECT id, name FROM hosts WHERE workspace_id = ?",
        (workspace_id,)).fetchall()}
    for row in rows:
        host = names.get(row["host_id"], str(row["host_id"]))
        where = ("every port" if row["port"] is None
                 else f"{row['protocol']}/{row['port']} on {row['family']}")
        until = row["until"] or "no expiry"
        print(f"{host:<24} {row['kind']:<8} {where:<22} until {until}")
    return 0


def main(argv=None) -> int:
    args = parse_args(argv)
    con = cli.open_database(args)
    try:
        db.init(con)
        # The prober's tables are created too, because a fresh box has never
        # run it and this command must work there.
        prober.init(con)
        intent.init(con)
        # alerts first: a recorded change points at the alert it raised, so
        # that table has to exist before this one references it.
        alerts.init(con)
        finding_alerts.init(con)
        return run(con, args)
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
