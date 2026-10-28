"""Declared intent, declared names and acknowledgement from the terminal.

    python -m app.intent_cli declare app-01 tcp 443 v4 open
    python -m app.intent_cli declare app-01 tcp 443 v4 closed
    python -m app.intent_cli clear app-01 tcp 443 v4
    python -m app.intent_cli name app-01 tcp 443 "caddy for the app"
    python -m app.intent_cli unname app-01 tcp 443
    python -m app.intent_cli list
    python -m app.intent_cli list --host app-01
    python -m app.intent_cli acknowledge app-01 tcp 443 v4
    python -m app.intent_cli unacknowledge app-01 tcp 443 v4

`declare` is the command that makes `conflict` and `intended` reachable. Until
it is run for a port, that port has no declaration and the join engine calls it
`unreviewed`, which is the honest default and stays the default.

**`name` takes no address family**, because it names the service behind the
port and the service does not change between v4 and v6 (`app/intent.py` owns
that reasoning). A name changes no state and no finding. It is what the
screens show for the port, said as declared, with anything measured kept
beside it.

**`acknowledge` does not take a state.** It reads the finding from
`app/join.py` and records the state that is actually there, so an
acknowledgement can never be filed against a finding nobody produced. A port
with no finding, and a port whose evidence supports none of the five states,
are both refused with the reason said out loud. The acknowledgement then
applies only while that state holds: change the declaration, and `unreviewed`
becomes `conflict`, which is a different finding and goes back on the list.

Nothing here probes anything or writes a rule anywhere. It records what a
person says they meant and what they say they have read.
"""

import argparse
import sys

from . import cli, db, intent, join, prober


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="intent", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def port_arguments(command) -> None:
        """The four things that identify one port on one address family. The
        choices here are the outer door and `app/intent.py` checks the same
        values again, because this command is not the only caller."""
        command.add_argument("host")
        command.add_argument("protocol", choices=sorted(intent.PROTOCOLS))
        command.add_argument("port", type=int)
        command.add_argument("family", choices=sorted(intent.FAMILIES))

    p_declare = sub.add_parser(
        "declare", help="record that this port is meant to be open or closed")
    port_arguments(p_declare)
    p_declare.add_argument("value", choices=sorted(intent.INTENTS))

    p_clear = sub.add_parser("clear", help="withdraw a declaration")
    port_arguments(p_clear)

    def named_port_arguments(command) -> None:
        """A port without an address family, which is how a name is keyed.
        `app/intent.py` argues why a name has no family."""
        command.add_argument("host")
        command.add_argument("protocol", choices=sorted(intent.PROTOCOLS))
        command.add_argument("port", type=int)

    p_name = sub.add_parser(
        "name", help="record what you call the service on this port")
    named_port_arguments(p_name)
    p_name.add_argument("value")

    p_unname = sub.add_parser("unname", help="withdraw a declared name")
    named_port_arguments(p_unname)

    p_list = sub.add_parser(
        "list",
        help="every live declaration, name and acknowledgement")
    p_list.add_argument("--host", default=None)

    p_ack = sub.add_parser(
        "acknowledge",
        help="record that this finding has been read and is not being acted on")
    port_arguments(p_ack)

    p_unack = sub.add_parser("unacknowledge",
                             help="put an acknowledged finding back on the list")
    port_arguments(p_unack)

    return parser.parse_args(argv)


def _where(args) -> str:
    return f"{args.protocol}/{args.port} on {args.family}"


def _named_where(args) -> str:
    """A name has no address family, so neither does its sentence."""
    return f"{args.protocol}/{args.port}"


def _print_declarations(con, host_name) -> None:
    rows = intent.list_declarations(con, host_name)
    if not rows:
        print("nothing is declared")
        return
    print("declared intent:")
    for row in rows:
        print(f"  {row['host_name']:<20} {row['protocol']}/{row['port']:<6}"
              f" {row['family']:<3} {row['intent']:<7} declared"
              f" {row['declared_at']}")


def _print_names(con, host_name) -> None:
    rows = intent.list_names(con, host_name)
    if not rows:
        return
    print()
    print("declared names:")
    for row in rows:
        print(f"  {row['host_name']:<20} {row['protocol']}/{row['port']:<6}"
              f" {row['name']}  declared {row['declared_at']}")


def _current_states(con, host_id) -> dict:
    """Every state this host's findings carry right now, keyed by port.

    Read from the join engine, so what the listing calls current is what the
    screen shows rather than a second opinion.
    """
    result = join.host_findings(con, host_id)
    if result is None:
        return {}
    return {(f.protocol, f.port, f.family): f.state for f in result.findings}


def _print_acknowledgements(con, host_name) -> None:
    rows = intent.list_acknowledgements(con, host_name)
    if not rows:
        return
    print()
    print("acknowledged findings:")
    states: dict[int, dict] = {}
    for row in rows:
        if row["host_id"] not in states:
            states[row["host_id"]] = _current_states(con, row["host_id"])
        now = states[row["host_id"]].get(
            (row["protocol"], row["port"], row["family"]))
        # An acknowledgement is about a finding, so saying only what was
        # acknowledged would let a stale one read as live.
        if now == row["state"]:
            applies = "still applies"
        elif now is None:
            applies = "lapsed, the port has no state now"
        else:
            applies = f"lapsed, it is {now} now"
        print(f"  {row['host_name']:<20} {row['protocol']}/{row['port']:<6}"
              f" {row['family']:<3} seen as {row['state']:<12} {applies}")


def _finding_for(con, args):
    """The finding the join engine produces for this port right now, or None.

    Read through `app/join.py` rather than reconstructed here, so the state an
    acknowledgement is filed against is the state the screen shows.
    """
    result = join.host_findings(con, intent.host_id_for(con, args.host))
    if result is None:
        return None
    for finding in result.findings:
        if (finding.protocol, finding.port, finding.family) == (
                args.protocol, args.port, args.family):
            return finding
    return None


def run(con, args) -> int:
    """One command against an open connection. Split out from `main` so the
    tests drive it without an environment variable, the same shape
    `app/users_cli.py` uses."""
    try:
        if args.command == "declare":
            result = intent.declare(con, args.host, args.protocol, args.port,
                                    args.family, args.value)
            print(f"{result.host_name} {_where(args)} is declared"
                  f" {result.intent}")
            if result.previous and result.previous != result.intent:
                print(f"  it was declared {result.previous} before this")
            return 0

        if args.command == "clear":
            if intent.clear(con, args.host, args.protocol, args.port, args.family):
                print(f"{args.host} {_where(args)} has no declaration now")
                return 0
            print(f"nothing was declared for {args.host} {_where(args)}",
                  file=sys.stderr)
            return 1

        if args.command == "name":
            result = intent.declare_name(con, args.host, args.protocol,
                                         args.port, args.value)
            print(f"{result.host_name} {_named_where(args)} is named"
                  f" {result.name}")
            if result.previous and result.previous != result.name:
                print(f"  it was named {result.previous} before this")
            return 0

        if args.command == "unname":
            if intent.clear_name(con, args.host, args.protocol, args.port):
                print(f"{args.host} {_named_where(args)} has no declared name"
                      " now")
                return 0
            print(f"nothing was named for {args.host} {_named_where(args)}",
                  file=sys.stderr)
            return 1

        if args.command == "list":
            _print_declarations(con, args.host)
            _print_names(con, args.host)
            _print_acknowledgements(con, args.host)
            return 0

        if args.command == "acknowledge":
            # Validated here as well as inside the store, because the lookup
            # below runs before the store is reached.
            intent.normalise(args.protocol, args.port, args.family)
            finding = _finding_for(con, args)
            if finding is None:
                print(f"no finding for {args.host} {_where(args)}."
                      " Nothing has raised this port, so there is nothing to"
                      " acknowledge", file=sys.stderr)
                return 1
            if finding.state is None:
                print(f"{args.host} {_where(args)} has no state."
                      f" The outside view says {finding.outside.word} and the"
                      " evidence supports none of the five states, so there is"
                      " no finding to acknowledge", file=sys.stderr)
                return 1
            result = intent.acknowledge(con, args.host, args.protocol, args.port,
                                        args.family, finding.state)
            print(f"{result.host_name} {_where(args)} is acknowledged as"
                  f" {result.state}")
            print("  it stops applying if that state changes")
            return 0

        if args.command == "unacknowledge":
            if intent.clear_acknowledgement(con, args.host, args.protocol,
                                            args.port, args.family):
                print(f"{args.host} {_where(args)} is on the list again")
                return 0
            print(f"nothing was acknowledged for {args.host} {_where(args)}",
                  file=sys.stderr)
            return 1
    except intent.IntentError as exc:
        print(f"cannot record that: {exc}", file=sys.stderr)
        return 1
    return 1


def main(argv=None) -> int:
    args = parse_args(argv)
    con = cli.open_database(args)
    try:
        db.init(con)
        # The prober's tables are created too, because the join engine reads
        # them and this command runs on boxes where the prober never has.
        prober.init(con)
        intent.init(con)
        return run(con, args)
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
