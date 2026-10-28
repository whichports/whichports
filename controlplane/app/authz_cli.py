"""Probe authorisations from the terminal.

    python -m app.authz_cli list
    python -m app.authz_cli start 185.199.108.153 --method dns-txt
    python -m app.authz_cli verify 3
    python -m app.authz_cli check 185.199.108.153
    python -m app.authz_cli revoke 185.199.108.153
    python -m app.authz_cli exclude 185.199.108.153
    python -m app.authz_cli unexclude 185.199.108.153
    python -m app.authz_cli sweep

`start` prints the token exactly once, with the name or the URL to publish it
at. Only its hash is stored, so a lost token means starting a new proof.

`check` is the gate itself (`app.authz.may_probe`), so what this prints is
what a prober would be told, word for word. It is here to be run rather than
reasoned about.

`--workspace` decides whose proof this is, and it defaults to 1, so every
command here does exactly what it did before workspaces existed. A proof
started in one workspace authorises nothing in another, which is the same rule
an agent-derived proof follows (`app/authz.py`, `account_for_workspace`).

`revoke` closes the proofs of an address that exist, and an agent still
sending from it proves it again. On a self-hosted instance with prober lines it
revokes the address on our prober API first (`_revoke`), and so does `exclude`. `exclude` is the stop that stays, for an
abuse report: it closes every proof of the address, for every account, and
nothing proves or probes it again until `unexclude`, which restores nothing
(`docs/PRODUCT.md` 5, the exclusion list, and `ops/RUNBOOK.md`).

Nothing in this file probes anything. `verify` reads evidence the operator
published, at the one name or the one address they nominated.
"""

import argparse
import sys

from . import authz, cli, db, dispatch, proberproofs

# The dashes read better on a command line than the underscores the database
# stores. This is the only place the two spellings meet.
CLI_METHODS = {"dns-txt": authz.METHOD_DNS_TXT, "http-token": authz.METHOD_HTTP_TOKEN}


def _print_authorizations(con) -> None:
    rows = authz.list_authorizations(con)
    if not rows:
        print("no authorisations recorded")
        return
    print("authorisations, newest first:")
    for row in rows:
        if row["revoked_at"]:
            state = f"revoked {row['revoked_at']}"
        elif row["expired_at"]:
            state = f"expired {row['expired_at']}"
        else:
            state = f"expires {row['expires_at']}"
        owner = row["host_name"] or row["account"]
        print(f"  {row['id']:>4} {row['target']:<40} {row['family']:<3}"
              f" {row['method']:<11} {owner:<16} {state}")


def _print_exclusions(con) -> None:
    rows = authz.list_exclusions(con)
    if not rows:
        return
    print()
    print("excluded:")
    for row in rows:
        state = (f"taken off {row['removed_at']}" if row["removed_at"]
                 else "never proved or probed")
        print(f"  {row['target']:<40} {row['family']:<3} since {row['added_at']}, {state}")


def _print_challenges(con) -> None:
    rows = authz.list_challenges(con)
    if not rows:
        return
    print()
    print("proofs started:")
    for row in rows:
        if row["cancelled_at"]:
            state = f"cancelled {row['cancelled_at']}"
        elif row["verified_at"]:
            state = f"verified {row['verified_at']}"
        else:
            state = f"unverified, closes {row['expires_at']}"
        print(f"  {row['id']:>4} {row['target']:<40} {row['method']:<11} {state}")
        print(f"       publish the token at {row['publish_at']}")


def _revoke(con, address: str) -> int:
    """Close the proofs of an address. On a self-hosted instance with prober
    lines our prober API is asked first, because since 2026-10-24 our
    registry decides which of the instance's addresses our probers touch
    (docs/PRODUCT.md 5g, `app/proberproofs.py`), so a revoke here alone would
    not stop them. When our API does not take it, nothing is changed here."""
    try:
        api = proberproofs.prober_api()
    except dispatch.TransportConfigError as exc:
        print(f"not revoked: {exc}", file=sys.stderr)
        return 1
    try:
        if api is None:
            closed = authz.revoke(con, address)
        else:
            closed = proberproofs.revoke(con, api, address,
                                         opener=proberproofs.opener())
    except authz.TargetError as exc:
        print(f"not an address we could have authorised: {exc}", file=sys.stderr)
        return 1
    except proberproofs.NotRevoked as refused:
        target, _family = authz.normalise_target(address)
        print(proberproofs.revoke_words(target, refused.code)
              + ". Nothing was changed here.", file=sys.stderr)
        return 1
    print(f"{closed} authorisation(s) closed, any proof in progress cancelled"
          + (", and revoked with the probers first" if api is not None else ""))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="authz", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="every authorisation and every proof started")

    p_start = sub.add_parser("start", help="mint a token for one address, printed once")
    p_start.add_argument("address")
    p_start.add_argument("--method", choices=sorted(CLI_METHODS), required=True)
    p_start.add_argument("--workspace", type=int, default=db.DEFAULT_WORKSPACE_ID,
                         help="which workspace this proof authorises for"
                              f" (default {db.DEFAULT_WORKSPACE_ID})")

    p_verify = sub.add_parser("verify", help="read the published evidence and record it")
    p_verify.add_argument("challenge_id", type=int)

    p_check = sub.add_parser("check", help="ask the gate about one address")
    p_check.add_argument("address")
    p_check.add_argument("--workspace", type=int, default=db.DEFAULT_WORKSPACE_ID,
                         help="which workspace is asking"
                              f" (default {db.DEFAULT_WORKSPACE_ID})")

    p_revoke = sub.add_parser("revoke", help="stop probing this address now")
    p_revoke.add_argument("address")

    p_exclude = sub.add_parser(
        "exclude", help="never prove or probe this address again, for any account")
    p_exclude.add_argument("address")

    p_unexclude = sub.add_parser(
        "unexclude", help="take an address off the exclusion list, restoring nothing")
    p_unexclude.add_argument("address")

    sub.add_parser("sweep", help="write down which authorisations have lapsed")

    args = parser.parse_args(argv)

    con = cli.open_database(args)
    try:
        db.init(con)
        authz.init(con)

        if args.command == "list":
            _print_authorizations(con)
            _print_challenges(con)
            _print_exclusions(con)
            return 0

        if args.command == "exclude":
            try:
                api = proberproofs.prober_api()
            except dispatch.TransportConfigError as exc:
                print(f"not excluded: {exc}", file=sys.stderr)
                return 1
            try:
                if api is None:
                    added, closed = authz.exclude(con, args.address)
                else:
                    # Our API first, so taking it off here later restores
                    # nothing for our probers either (`proberproofs.exclude`).
                    added, closed = proberproofs.exclude(
                        con, api, args.address, opener=proberproofs.opener())
            except authz.TargetError as exc:
                print(f"not an address we could ever probe: {exc}", file=sys.stderr)
                return 1
            except proberproofs.NotRevoked as refused:
                target, _family = authz.normalise_target(args.address)
                print(proberproofs.revoke_words(target, refused.code)
                      + ". Nothing was changed here.", file=sys.stderr)
                return 1
            entry = authz.active_exclusion(con, args.address)
            proofs = "proof" if closed == 1 else "proofs"
            if added:
                print(f"{entry['target']} is excluded, {closed} {proofs} of it closed."
                      " No account proves or probes it until unexclude.")
            else:
                print(f"{entry['target']} was already excluded, since"
                      f" {entry['added_at']}. {closed} {proofs} of it closed.")
            return 0

        if args.command == "unexclude":
            try:
                removed = authz.unexclude(con, args.address)
            except authz.TargetError as exc:
                print(f"not an address we could ever probe: {exc}", file=sys.stderr)
                return 1
            target, _family = authz.normalise_target(args.address)
            if not removed:
                print(f"{target} is not excluded", file=sys.stderr)
                return 1
            print(f"{target} is no longer excluded. Nothing was restored: it is"
                  " probed again only after a new proof.")
            return 0

        if args.command == "start":
            try:
                challenge = authz.start_proof(
                    con, args.address, CLI_METHODS[args.method],
                    account=authz.account_for_workspace(args.workspace))
            except authz.TargetError as exc:
                print(f"cannot authorise this address: {exc}", file=sys.stderr)
                return 1
            print(f"proof {challenge.id} started for {challenge.target}"
                  f" ({challenge.family}).")
            print()
            if challenge.method == authz.METHOD_DNS_TXT:
                print(f"  publish a TXT record at {challenge.publish_at}")
            else:
                print(f"  serve this at {challenge.publish_at}")
            print("  holding exactly this token, shown once:")
            print()
            print(f"  {challenge.token}")
            print()
            print(f"then run: python -m app.authz_cli verify {challenge.id}")
            print(f"unverified proofs close at {challenge.expires_at}")
            return 0

        if args.command == "verify":
            result = authz.verify_proof(con, args.challenge_id)
            if result.recorded:
                print(result.reason)
                return 0
            print(result.reason, file=sys.stderr)
            return 1

        if args.command == "check":
            decision = authz.may_probe(
                con, args.address,
                account=authz.account_for_workspace(args.workspace))
            print(f"{'yes' if decision.allowed else 'no'}: {decision.reason}")
            return 0 if decision.allowed else 1

        if args.command == "revoke":
            return _revoke(con, args.address)

        if args.command == "sweep":
            result = authz.sweep(con)
            for target in result["expired"]:
                print(f"expired: {target}")
            print(f"checked {result['checked']}, {len(result['expired'])} expired")
            return 0
    finally:
        con.close()
    return 1


if __name__ == "__main__":
    sys.exit(main())
