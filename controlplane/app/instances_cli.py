"""Issue and end the keys a self-hosted instance uses our probers with.

    python -m app.instances_cli add --name freedom
    python -m app.instances_cli list
    python -m app.instances_cli reissue --name freedom --kind api
    python -m app.instances_cli revoke --name freedom
    python -m app.instances_cli log --address 203.0.113.9

`app/instances.py` owns the storage and the reasoning. `add` prints two keys,
once, and nothing can print them again: the API key goes into the instance's
control plane configuration, the proof key into its agents' install command.
It prints them first as the invite line (`app/invite.py`), which holds both
and our API's host, and which the self-hosted installer asks for. Send it to
the tester over a channel you would send a password over.

`revoke` ends both keys and every proof the instance made, at once. There is
no undo. A tester who comes back gets a new instance with new keys.

`log` is for an abuse report. It prints, for one address, every day an
instance's batch could reach it from our probers, and every proof an instance
holds or held for it, which together say who asked and on what evidence.
"""

import argparse
import sqlite3
import sys

from . import authz, cli, db, instances, invite, proberapi, publicurl


def _print_list(con) -> int:
    found = instances.list_all(con)
    if not found:
        print("no instances. Nothing but this control plane uses the probers.")
        print("add one with: python -m app.instances_cli add --name NAME")
        return 0
    for instance in found:
        print(f"  {instance.name}")
        print(f"    account    {instance.account}")
        print(f"    state      {'revoked ' + instance.revoked_at if instance.revoked_at else 'live'}")
        print(f"    added      {instance.created_at}")
        print(f"    made       {instance.origin or 'not recorded'}")
        # The address an instance that signed up keeps, for reaching whoever
        # runs it. To this terminal only, never to a log.
        contact = instances.contact_of(con, instance.id)
        if contact:
            print(f"    address    {contact}")
        for row in instances.key_rows(con, instance.id):
            state = f"revoked {row['revoked_at']}" if row["revoked_at"] else "live"
            print(f"    {row['kind']:<5} key  issued {row['created_at']}, {state}")
    return 0


def _print_log(con, address: str) -> int:
    try:
        canonical, _family = authz.normalise_target(address)
    except authz.TargetError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    excluded = authz.active_exclusion(con, canonical)
    if excluded is not None:
        print(f"  excluded since {excluded['added_at']}: no account proves or"
              " probes it")
    days = proberapi.log_for_target(con, canonical)
    proofs = [row for row in authz.list_authorizations(con)
              if row["target"] == canonical
              and authz.is_instance_account(row["account"])]
    if not days and not proofs:
        print(f"no instance asked for {canonical} in the last"
              f" {proberapi.LOG_RETENTION_SECONDS // 86400} days, and none"
              " proved it")
        return 0
    names = {instance.account: instance.name for instance in instances.list_all(con)}
    for row in days:
        print(f"  {row['day']}  {row['instance_name'] or row['instance_id']}"
              f"  from {row['vantage']}  {row['batches']} batches,"
              f" at most {row['connects']} connects,"
              f" {row['first_at']} to {row['last_at']}")
    for row in proofs:
        state = ("revoked " + row["revoked_at"] if row["revoked_at"]
                 else "lapsed " + row["expired_at"] if row["expired_at"]
                 else "until " + row["expires_at"])
        print(f"  proof  {names.get(row['account'], row['account'])}"
              f"  by {row['method']}, verified {row['verified_at']}, {state}")
    return 0


def run(con, args) -> int:
    try:
        if args.command == "list":
            return _print_list(con)
        if args.command == "add":
            # Our own address, read before any key is made: a setting that
            # cannot give a host stops the command with nothing issued.
            try:
                host = publicurl.host()
            except publicurl.PublicUrlError as exc:
                print(str(exc), file=sys.stderr)
                return 1
            # By hand on the box is what an invite is.
            issued = instances.add(con, args.name, origin=authz.ORIGIN_INVITED)
            print(f"added {issued.instance.name}, account {issued.instance.account}")
            print()
            print("These are shown once. Only their hashes are stored.")
            # The line the tester's installer asks for. It holds both keys
            # below and our API's host, and the instance takes it apart into
            # its three settings (app/invite.py says how the keys stay apart).
            try:
                print(f"  invite     {invite.line(host, issued.api_key, issued.proof_key)}")
                print("             the one line the tester's installer asks for")
            except invite.InviteError as exc:
                print(f"  invite     none: {exc}")
            print(f"  API key    {issued.api_key}")
            print("             for the instance's control plane")
            print(f"  proof key  {issued.proof_key}")
            print("             for the instance's agents")
            return 0
        if args.command == "reissue":
            key = instances.reissue(con, args.name, args.kind)
            print(f"new {args.kind} key for {args.name}, shown once:")
            print(f"  {key}")
            print(f"the old {args.kind} key stopped working just now.")
            if args.kind == instances.KIND_PROOF:
                print("agents holding the old proof key stop proving their"
                      " addresses, which lapse an hour after the last proof."
                      " Re-enrol the instance's servers with the new key.")
            return 0
        if args.command == "log":
            return _print_log(con, args.address)
        if args.command == "revoke":
            instance = instances.revoke(con, args.name,
                                        unused=getattr(args, "unused", False))
            print(f"revoked {instance.name} at {instance.revoked_at}. Both keys"
                  " and every proof it made have ended.")
            return 0
    except instances.InstanceError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 1


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="instances", description=__doc__.split("\n`app/")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="every instance, live or revoked, with its keys")

    p_add = sub.add_parser("add", help="add an instance and print its two keys")
    p_add.add_argument("--name", required=True, metavar="NAME")

    p_reissue = sub.add_parser("reissue", help="replace one key of an instance")
    p_reissue.add_argument("--name", required=True, metavar="NAME")
    p_reissue.add_argument("--kind", required=True, choices=instances.KINDS)

    p_revoke = sub.add_parser("revoke", help="end an instance, its keys and its proofs")
    p_revoke.add_argument("--name", required=True, metavar="NAME")
    # A signup instance whose line was lost: ended the way the sweep ends
    # an unused one, so its address may sign up again at once. Without it a
    # revoke keeps the address out for 30 days (instances.address_taken).
    p_revoke.add_argument("--unused", action="store_true",
                          help="end it as unused, so its address may sign up again")

    p_log = sub.add_parser("log", help="who asked our probers for an address, for an abuse report")
    p_log.add_argument("--address", required=True, metavar="ADDRESS")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        con = cli.open_database(args)
    except sqlite3.Error as exc:
        print(f"the database could not be used: {exc}", file=sys.stderr)
        return 1
    try:
        # revoke closes authorisations, so the registry's own tables have to
        # exist on a database where no proof was ever made. Additive and
        # idempotent, the same as every other command here.
        db.init(con)
        authz.init(con)
        instances.init(con)
        proberapi.init(con)
        return run(con, args)
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
