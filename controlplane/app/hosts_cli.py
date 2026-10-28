"""Host administration from the terminal.

    python -m app.hosts_cli add almabox
    python -m app.hosts_cli list
    python -m app.hosts_cli revoke almabox
    python -m app.hosts_cli list --workspace 2

`add` prints the credential exactly once, together with the enroll command to
run on the host. It is not stored and cannot be shown again: a lost
credential means revoke and re-add, which is the honest recovery story. The
dashboard grows the same actions later; this exists so the ingest is usable
and testable on its own.

`--workspace` decides which workspace a host is enrolled into and which
workspace is listed. It defaults to 1, which is where every host enrolled
before workspaces existed was backfilled, so every command here without the
flag does exactly what it did before.
"""

import argparse
import sys

from . import cli, db, store


def main() -> int:
    parser = argparse.ArgumentParser(prog="hosts", description=__doc__)
    cli.add_create_flag(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    def workspace_argument(command) -> None:
        command.add_argument("--workspace", type=int,
                             default=db.DEFAULT_WORKSPACE_ID,
                             help="which workspace to work in"
                                  f" (default {db.DEFAULT_WORKSPACE_ID})")

    p_add = sub.add_parser("add", help="enroll a new host, prints its credential once")
    p_add.add_argument("name")
    p_add.add_argument("--address", action="store_true",
                       help="a server watched from outside only: no agent, no "
                            "credential, probed on the addresses you prove "
                            "(python -m app.authz_cli start)")
    workspace_argument(p_add)
    p_list = sub.add_parser("list", help="every host, with freshness and revocation")
    workspace_argument(p_list)
    p_revoke = sub.add_parser("revoke", help="stop accepting this host's credential")
    p_revoke.add_argument("name")
    workspace_argument(p_revoke)
    p_prune = sub.add_parser(
        "prune", help="delete every never-reported agent host (the add-server"
                      " ghosts). Reporting hosts and address hosts are untouched")
    workspace_argument(p_prune)
    p_delete = sub.add_parser(
        "delete", help="delete a revoked host with everything stored about it:"
                       " documents, findings, alerts, proofs, declarations and"
                       " outside measurements. Revoke it first")
    p_delete.add_argument("name")
    workspace_argument(p_delete)
    args = parser.parse_args()

    con = cli.open_database(args)
    try:
        db.init(con)
        if args.command == "add":
            if args.address:
                try:
                    store.add_address_host(con, args.name, workspace_id=args.workspace)
                except Exception as exc:
                    print(f"could not add {args.name!r}: {exc}", file=sys.stderr)
                    return 1
                print(f"host {args.name} added, watched from outside only.")
                print("prove an address it may be probed on:")
                print(f"  python -m app.authz_cli start <address> --method http-token")
                return 0
            try:
                _, credential = store.add_host(con, args.name,
                                               workspace_id=args.workspace)
            except Exception as exc:
                # sqlite's unique-name violation lands here; say it plainly.
                print(f"could not add {args.name!r}: {exc}", file=sys.stderr)
                return 1
            print(f"host {args.name} added. Its credential, shown exactly once:")
            print()
            print(f"  {credential}")
            print()
            print("run on the host (server URL as deployed):")
            print(f"  whichports-agent enroll --server=https://... --credential={credential}")
            return 0
        if args.command == "list":
            for row in store.list_hosts(con, workspace_id=args.workspace):
                state = "revoked" if row["revoked_at"] else "active"
                last = row["last_report_at"] or "never reported"
                print(f"{row['name']:24} {state:8} last report: {last}")
            return 0
        if args.command == "revoke":
            if store.revoke_host(con, args.name, workspace_id=args.workspace):
                print(f"{args.name} revoked: its reports are refused from now on")
                return 0
            print(f"no active host named {args.name!r} in workspace"
                  f" {args.workspace}", file=sys.stderr)
            return 1
        if args.command == "prune":
            names = store.prune_never_reported(con, workspace_id=args.workspace)
            if not names:
                print("nothing to prune: no never-reported agent host in"
                      f" workspace {args.workspace}")
                return 0
            for name in names:
                print(f"deleted {name}")
            print(f"pruned {len(names)} never-reported host"
                  f"{'s' if len(names) != 1 else ''}")
            return 0
        if args.command == "delete":
            if store.delete_host(con, args.name, workspace_id=args.workspace):
                print(f"{args.name} deleted with everything stored about it")
                return 0
            print(f"no revoked host named {args.name!r} in workspace"
                  f" {args.workspace}: revoke it first, or check the name",
                  file=sys.stderr)
            return 1
    finally:
        con.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
