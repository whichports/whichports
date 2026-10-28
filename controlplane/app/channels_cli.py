"""Say where alerts go, from the terminal.

    python -m app.channels_cli list
    python -m app.channels_cli add --type webhook --label "ops hook" \
        --env WHICHPORTS_WEBHOOK_URL
    python -m app.channels_cli add --type slack --label "ops slack" \
        --env WHICHPORTS_SLACK_URL
    python -m app.channels_cli add --type discord --label "ops discord" \
        --env WHICHPORTS_DISCORD_URL
    python -m app.channels_cli add --type telegram --label "ops telegram" \
        --env WHICHPORTS_TELEGRAM_TOKEN --chat-id -1001234567890
    python -m app.channels_cli test --label "ops slack"
    python -m app.channels_cli off --label "ops slack"
    python -m app.channels_cli on  --label "ops slack"
    python -m app.channels_cli remove --label "ops slack"

`app/channels.py` owns the storage and the reasoning. The one thing worth
repeating here, because it is the thing an operator will get wrong first:
**`--env` takes the NAME of an environment variable, not a URL and not an
address.** The value stays in `/etc/whichports/alerts.env` and is read by the
sweep at send time. Nothing this command writes can hold a credential.

**Telegram is the one channel that needs two things**, and only one of them is
a secret. `--env` names the variable holding the bot token, which is the
credential. `--chat-id` is the chat it posts in, which the Bot API documents as
an identifier and not as a credential, so it is stored on the row. One bot token
can post to many chats, so the chat id is part of what makes a channel a
destination and not a decoration on it.

`list` prints the variable name each channel reads and whether that variable is
set in this process's own environment, which is what makes a quiet channel
diagnosable. It never prints a value.
"""

import argparse
import sqlite3
import sys
from dataclasses import replace

from . import accounts, channels, cli, db, notify, outbound, senders


def _print_list(con, env=None) -> int:
    found = channels.live(con)
    if not found:
        print("no channels. Alerts are recorded and delivered nowhere.")
        print("add one with: python -m app.channels_cli add --type webhook"
              " --label NAME --env WHICHPORTS_WEBHOOK_URL")
        return 0
    for channel in found:
        state = "on" if channel.enabled else "off"
        ws = channel.workspace_id
        # Set or not, never the value. A person debugging a channel that is not
        # delivering needs to know which of the two halves is missing.
        has = "set" if channel.resolve(env) else "NOT SET in this environment"
        print(f"  {channel.label}")
        print(f"    type    {channel.type}")
        print(f"    state   {state}")
        print(f"    workspace {ws}")
        print(f"    reads   {channel.destination_env}  ({has})")
        rule = channels.TYPE_RULES[channel.type]
        if rule is not None:
            print(f"    {rule.field:<7} {channel.destination_extra}")
    return 0


def _send_test(con, label, env=None) -> int:
    """One test message to one channel, from a shell.

    **This is the command the Integrations screen hands over**, so it has to actually
    send. Send test in a channel's row menu asks the control plane first, and
    the control plane can only send where it can resolve the destination: a row
    naming a variable is read from the sweep unit's environment, and mail needs
    the relay password, and the process serving the dashboard has neither
    (docs/RECORD.md #266). For those rows it answers with this line instead of
    pretending. Run it where the variables are:

        set -a; . /etc/whichports/alerts.env; set +a
        python -m app.channels_cli test --label "ops slack"

    It replaces `python -m app.sweep_cli --dry-run` in that answer, which was
    the wrong command to name: that flag is "sweep, print, send nothing", so it
    could never deliver the test the answer promised.
    """
    # The same lookup `app/channels.py` and `app/ingest.py` both already do
    # inline. A shared helper would be the third spelling of it and is a
    # refactor of their code, not part of this.
    found = [c for c in channels.live(con) if c.label == label]
    if not found:
        print(f"no channel called {label!r}", file=sys.stderr)
        return 1
    channel = found[0]

    if channel.type == channels.TYPE_EMAIL:
        to = channel.resolve(env)
        if not to:
            print(f"{channel.destination_env} is not set in this environment,"
                  " so there is no recipient to send to", file=sys.stderr)
            return 1
        config = notify.config_from_env(env)
        if not config.host:
            print("the mail relay is not configured in this environment."
                  " Source /etc/whichports/alerts.env first", file=sys.stderr)
            return 1
        subject, body, html = notify.format_test()
        sent, reason = notify.send(subject, body,
                                   replace(config, to=to,
                                           sender=config.sender or to),
                                   html=html)
    else:
        if not channel.resolve(env):
            print(f"{channel.destination_env} is not set in this environment,"
                  " so this channel has nowhere to deliver to", file=sys.stderr)
            return 1
        sent, reason = senders.deliver_test(channel, env)

    if sent:
        print(f"sent a test message to {channel.label}")
        return 0
    # The reason is a class name or one of our own sentences, never an
    # endpoint's free text and never a destination (SI-8, app/webhook.py).
    print(f"could not send to {channel.label}: {reason}", file=sys.stderr)
    # For an operator, and never on a screen: which setting lets a private
    # address through (`app/outbound.py`).
    if outbound.operator_note(reason):
        print(outbound.operator_note(reason), file=sys.stderr)
    return 1


def _backfill_accounts(con) -> int:
    """The email channel every account gets since 2026-09-20, for the accounts
    made before it (`docs/RECORD.md` 4.186). Run once, by hand.

    **Only a workspace holding no email row at all is touched**, enabled or
    not. One that holds a row was set up by somebody, and a second row for a
    second address there would be mail nobody asked for. A disabled account
    gets none. Safe to run twice: the second run finds the rows of the first.

    Prints the workspace and the count, never an address.
    """
    accounts.init(con)
    added = {}
    for user in accounts.list_users(con):
        if user["disabled_at"]:
            continue
        workspace_id = user["workspace_id"]
        if workspace_id not in added:
            if channels.live(con, channels.TYPE_EMAIL,
                             workspace_id=workspace_id):
                continue
            added[workspace_id] = 0
        if channels.ensure_account_email(con, user["email"], workspace_id):
            added[workspace_id] += 1
    for workspace_id, count in sorted(added.items()):
        print(f"workspace {workspace_id}: {count} email"
              f" channel{'' if count == 1 else 's'} added")
    if not added:
        print("nothing to add: every workspace with an account holds an"
              " email channel")
    return 0


def run(con, args, env=None) -> int:
    if args.command == "list":
        return _print_list(con, env)

    if args.command == "test":
        return _send_test(con, args.label, env)

    if args.command == "add":
        try:
            channel = channels.add(con, args.type, args.label, args.env,
                                   destination_extra=args.chat_id or "",
                                   destination=args.destination or "",
                                   workspace_id=args.workspace)
        except channels.ChannelError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if channel.destination:
            # The host, never the value, for the same reason the screen shows
            # only the host: the secret in every one of these is the path.
            print(f"added {channel.label}, a {channel.type} channel posting to"
                  f" {channel.hint()}")
            return 0
        print(f"added {channel.label}, a {channel.type} channel reading"
              f" {channel.destination_env}")
        if not channel.resolve(env):
            # Said at the moment it is created rather than discovered later
            # when an alert does not arrive.
            print(f"{channel.destination_env} is not set in this environment,"
                  " so this channel delivers nothing yet. The sweep reads it"
                  " from /etc/whichports/alerts.env on the box.")
        return 0

    if args.command in ("on", "off"):
        if not channels.set_enabled(con, args.label, args.command == "on"):
            print(f"no channel called {args.label!r}", file=sys.stderr)
            return 1
        print(f"{args.label} is {args.command}")
        return 0

    if args.command == "backfill-accounts":
        return _backfill_accounts(con)

    if args.command == "remove":
        if not channels.remove(con, args.label):
            print(f"no channel called {args.label!r}", file=sys.stderr)
            return 1
        print(f"removed {args.label}")
        return 0
    return 1


def parse_args(argv=None):
    usage = __doc__.split("\n\n")[0]
    parser = argparse.ArgumentParser(prog="channels", description=usage)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="every channel, and whether its variable is set")
    sub.add_parser("backfill-accounts",
                   help="once: give every workspace that holds no email"
                        " channel one for each of its accounts")

    p_add = sub.add_parser("add", help="add a channel")
    p_add.add_argument("--type", required=True, choices=list(channels.TYPES))
    p_add.add_argument("--label", required=True,
                       help="what to call it. Its row is edited, tested and removed by this name")
    p_add.add_argument("--destination", default="", metavar="URL",
                       help="the destination itself, the ordinary way. Use this"
                            " or --env, never both")
    p_add.add_argument("--env", default="", metavar="NAME",
                       help="the NAME of the environment variable holding the"
                            " destination, never the destination itself")
    # A Telegram group chat id is negative, and argparse takes it either as
    # `--chat-id -100...` or `--chat-id=-100...`. Measured rather than assumed,
    # and a test covers both forms, because the first thing an operator types
    # here is a leading dash.
    p_add.add_argument("--chat-id", default="", metavar="ID",
                       help="telegram only: the chat to post in. Not the bot"
                            " token, which is the credential and goes in --env")
    p_add.add_argument("--workspace", type=int, default=db.DEFAULT_WORKSPACE_ID,
                       help="which workspace's alerts this channel takes and"
                            " whose screen lists it, the same flag users_cli"
                            " add carries")

    for name, help_text in (("on", "switch a channel on"),
                            ("off", "switch a channel off, keeping its row"),
                            ("remove", "take a channel away"),
                            ("test", "send one test message to a channel")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--label", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        con = cli.open_database(args)
    except sqlite3.Error as exc:
        print(f"the database could not be used: {exc}", file=sys.stderr)
        return 1
    try:
        db.init(con)
        channels.init(con)
        return run(con, args)
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
