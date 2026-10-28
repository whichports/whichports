"""Read the beta list on the box, and take somebody off it.

    python -m app.betasignup_cli count
    python -m app.betasignup_cli list
    python -m app.betasignup_cli remove someone@example.org

`app/betasignup.py` owns what the list holds. `remove` exists because the
landing page promises a way off: "To leave the list, write to
hello@whichports.com". Whoever reads that mail runs this.

`list` prints addresses, which are contact data. It prints them to the
terminal it was run from and nowhere else, so do not paste its output into
the repository, a card or a chat.
"""
import argparse
import sys

from . import betasignup, cli


def run(con, args) -> int:
    betasignup.init(con)
    if args.command == "count":
        print(betasignup.count(con))
        return 0
    if args.command == "list":
        rows = betasignup.list_all(con)
        for row in rows:
            print(f"{row['created_at']}  {row['servers'] or '-':7}  {row['email']}")
        print(f"{len(rows)} on the list")
        return 0
    if args.command == "remove":
        try:
            email = betasignup.normalise_email(args.email)
        except betasignup.InvalidEmail:
            print("that is not an address this list could hold", file=sys.stderr)
            return 1
        if betasignup.remove(con, email):
            print(f"removed. {betasignup.count(con)} left on the list")
            return 0
        print("no such address on the list", file=sys.stderr)
        return 1
    return 1


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="betasignup", description=__doc__.split("\n`app/")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("count", help="how many are on the list")
    sub.add_parser("list", help="everybody on the list, oldest first")
    p_remove = sub.add_parser("remove", help="take one address off the list")
    p_remove.add_argument("email")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    con = cli.open_database(args)
    try:
        return run(con, args)
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
