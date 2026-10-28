"""The Hetzner Cloud provider leg from the terminal.

    python -m app.hetzner_cli show --workspace 1     # fetch and print, write nothing
    python -m app.hetzner_cli fetch --workspace 1    # fetch and store one snapshot
    python -m app.hetzner_cli latest --workspace 1   # print the stored snapshot

The same reason `hosts_cli` exists: the provider leg has to be usable and
testable before the dashboard grows a place to show it. Nothing here is wired
into the UI yet, and the evidence panel still says the provider column is not
connected.

The token is one workspace's, stored on the Integrations screen and read
from the database (`app/hetzner.py`, record 4.178); every command takes
`--workspace`, 1 if omitted. With no token stored every command says so and
does nothing, which is the same "off unless configured" posture the alert
sender takes.

Exit codes are for a person, since no timer runs this. Not configured is a
normal state and exits 0. A fetch that failed exits 1, with the typed kind on
stderr and nothing the provider wrote.
"""

import argparse
import sys

from . import cli, hetzner


def _address_line(label: str, addresses: tuple[str, ...]) -> str:
    """One family per line, and a family with no entry says so.

    This is the display half of PRODUCT.md 4b rule 3. A rule listing only
    `0.0.0.0/0` says nothing about IPv6, and printing the two families on one
    line would let a reader carry the v4 answer over to v6 by eye.
    """
    return f"      {label}: " + (", ".join(addresses) if addresses else "none listed")


def print_inventory(inventory: hetzner.Inventory, out=None) -> None:
    # Resolved here rather than in the signature: a default argument binds
    # sys.stdout once at import, which makes this unredirectable.
    out = sys.stdout if out is None else out
    print(f"servers ({len(inventory.servers)})", file=out)
    for server in inventory.servers:
        ipv4 = server.ipv4 or "not present"
        ipv6 = server.ipv6_network or "not present"
        if server.firewalls:
            attached = ", ".join(f"firewall {ref.id} {ref.status}" for ref in server.firewalls)
        else:
            attached = "no firewall attached"
        print(f"  {server.name}  [{server.status}]", file=out)
        print(f"    ipv4 {ipv4}", file=out)
        print(f"    ipv6 network {ipv6}", file=out)
        print(f"    {attached}", file=out)

    print(f"firewalls ({len(inventory.firewalls)})", file=out)
    for firewall in inventory.firewalls:
        print(f"  {firewall.name}  id {firewall.id}", file=out)
        for target in firewall.applied_to:
            if target.type == "server":
                print(f"    applied to server {target.server_id}", file=out)
            elif target.type == "label_selector":
                resolved = ", ".join(str(i) for i in target.resolved_server_ids) or "no server"
                print(f"    applied by label selector {target.label_selector}"
                      f", matching {resolved}", file=out)
            else:
                print(f"    applied to {target.type}", file=out)
        if not firewall.applied_to:
            print("    applied to nothing", file=out)
        for rule in firewall.rules:
            port = f" port {rule.port}" if rule.port else ""
            print(f"    {rule.direction} {rule.protocol}{port}", file=out)
            if rule.description:
                print(f"      described as: {rule.description}", file=out)
            addresses = rule.source_ips if rule.direction == "in" else rule.destination_ips
            side = "source" if rule.direction == "in" else "destination"
            print(_address_line(f"{side} ipv4", addresses.v4), file=out)
            print(_address_line(f"{side} ipv6", addresses.v6), file=out)
            if addresses.unparsed:
                print(_address_line(f"{side} not recognised", addresses.unparsed), file=out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="hetzner", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name, text in (("show", "fetch and print, write nothing"),
                       ("fetch", "fetch and store one snapshot"),
                       ("latest", "print the stored snapshot")):
        sub.add_parser(name, help=text).add_argument(
            "--workspace", type=int, default=1,
            help="the workspace whose token and snapshot this is about, 1 if omitted")
    args = parser.parse_args(argv)

    # Before anything reads a variable: the database path comes from the
    # environment file the units read, and a shell inherits it from neither
    # (app/cli.py). The token itself lives in the database, per workspace.
    cli.load_environment()

    con = cli.open_database(args)
    try:
        hetzner.init(con)
        held = hetzner.tokens(con, args.workspace)
        if args.command == "latest":
            stored = hetzner.latest_snapshots(con, args.workspace)
    finally:
        con.close()

    # One token per project since 2026-09-27 (record 4.206), so every command
    # goes through each token the workspace holds, and says which one by its
    # id and hint before what it read. Never the token itself.
    if args.command == "latest":
        found = [(token_id, snapshot) for token_id, snapshot in stored
                 if snapshot is not None]
        if not found:
            print(f"no snapshot stored yet for workspace {args.workspace}")
            return 0
        hints = {token["id"]: token["hint"] for token in held}
        for token_id, snapshot in found:
            print(f"token {token_id} {hints.get(token_id, '')}".rstrip())
            print(f"fetched at {snapshot.fetched_at}")
            print_inventory(hetzner.parse_snapshot(snapshot))
        return 0

    if not held:
        # Off unless connected. Not an error: this is what a fresh workspace
        # looks like and it must not make a shell script go red.
        print(f"not connected: workspace {args.workspace} holds no Hetzner Cloud"
              " token. Connect one on the Integrations screen")
        return 0
    failed = False
    for token in held:
        print(f"token {token['id']} {token['hint']}")
        con = cli.open_database(args)
        try:
            hetzner.init(con)
            value = hetzner.token_for(con, args.workspace, token["id"])
        finally:
            con.close()
        client = hetzner.client_for(value)
        try:
            snapshot = client.fetch_snapshot()
        except hetzner.ProviderError as exc:
            # The typed kind, never anything the provider wrote. The other
            # tokens are still read: one project's refusal says nothing
            # about another's.
            print(f"fetch failed: {exc.kind}", file=sys.stderr)
            failed = True
            continue
        print(f"fetched at {snapshot.fetched_at}")
        if client.rate_limit.remaining is not None:
            print(f"rate limit remaining: {client.rate_limit.remaining}")
        print_inventory(hetzner.parse_snapshot(snapshot))
        if args.command == "fetch":
            con = cli.open_database(args)
            try:
                hetzner.init(con)
                hetzner.store_snapshot(con, snapshot, workspace_id=args.workspace,
                                       token_id=token["id"])
            finally:
                con.close()
            print(f"snapshot stored for workspace {args.workspace}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
