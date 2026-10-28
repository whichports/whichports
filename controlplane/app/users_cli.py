"""Operator accounts from the terminal.

    python -m app.users_cli add sysadmin@example.com
    python -m app.users_cli list
    python -m app.users_cli name sysadmin@example.com "Robin Sample"
    python -m app.users_cli passwd sysadmin@example.com
    python -m app.users_cli disable sysadmin@example.com
    python -m app.users_cli enable sysadmin@example.com
    python -m app.users_cli erase sysadmin@example.com
    python -m app.users_cli erase sysadmin@example.com --yes
    python -m app.users_cli sign-out sysadmin@example.com
    python -m app.users_cli admin list
    python -m app.users_cli admin grant sysadmin@example.com
    python -m app.users_cli admin revoke sysadmin@example.com
    python -m app.users_cli 2fa status sysadmin@example.com
    python -m app.users_cli 2fa enable sysadmin@example.com
    python -m app.users_cli 2fa disable sysadmin@example.com
    python -m app.users_cli 2fa reset-codes sysadmin@example.com
    python -m app.users_cli link sysadmin@example.com google
    python -m app.users_cli identities sysadmin@example.com
    python -m app.users_cli unlink sysadmin@example.com google
    python -m app.users_cli providers
    python -m app.users_cli providers --check

This is the only way an account comes into being, on purpose and by the same
reasoning `app.hosts_cli` exists for hosts: the first user is made by whoever
is already on the box, so there is no signup form on the internet before anyone
has decided there should be one.

**An account belongs to one workspace and sees only that workspace's servers.**
`add --workspace` decides which, and it defaults to 1, which is where every
account and every host predating workspaces was backfilled. `list` says which
workspace each account is in.

**A Google or Microsoft sign-in is connected here too**, and `link` is the
reason a valid provider token signs nobody in on its own. It prints a
single-use URL to open in a browser, and only completing the provider's own
consent screen behind that URL binds the identity to this account. The
reasoning, including why an email address is never used to match an incoming
token to an account, is the docstring of `app/identities.py` and is worth
reading before changing any of it.

**`providers` answers "is this actually configured", which is the question that
had no other answer.** It says, per provider, which environment variables this
process can really see, the exact redirect URI to register, whether the button
will appear, and who the sign-in is connected to. It never prints a secret.
`--check` also fetches each provider's discovery document, which is the only
step here that needs the network.

**The admin flag is granted here and nowhere else**, for the same reason. It
is not a role and it is not a second workspace: it is one flag that adds the
Admin screen, where the service-wide numbers are. `app/accounts.py` says why no
email address is written into the code.

**Two-factor is turned on here and nowhere else**, for the same reason. An
enrolment page on the internet is a surface, and this product has exactly one
operator account per organisation, so the person who would use that page is
already the person with a shell on the box. It also means the lockout path is
never a support conversation: `2fa disable` is right here.

**The password is never an argument.** Command lines are visible to every user
on the machine through `ps`, and they land in shell history. It is asked for at
the prompt, twice, with no echo. When standard input is not a terminal one line
is read from it instead, so a provisioning script can pipe it in without the
password ever appearing in an argument list either.
"""

import argparse
import getpass
import sys
import time
from dataclasses import replace

from . import (accounts, cli, db, erase, identities, notify, oidc, onetime,
               publicurl, totp)
from .providers import PROVIDERS


def read_password(confirm: bool = True) -> str:
    """Ask twice at a terminal, or take one line from a pipe."""
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("password: ")
    if confirm and first != getpass.getpass("again: "):
        raise SystemExit("the two passwords do not match, nothing was changed")
    return first


def build_parser() -> argparse.ArgumentParser:
    """The whole command line, in one function so a test can drive the
    real parser rather than a Namespace built by hand. A subcommand that
    is wired wrongly then fails a test instead of failing on the box."""
    parser = argparse.ArgumentParser(prog="users", description=__doc__)
    # On the top level parser rather than on `add`, because the very first run
    # on a fresh machine is `add` and the second is `list`, and being refused
    # by the one that only reads would be a puzzle.
    cli.add_create_flag(parser)
    sub = parser.add_subparsers(dest="command", required=True)
    p_add = sub.add_parser("add", help="create an account, asks for the password")
    p_add.add_argument("email")
    p_add.add_argument("--workspace", type=int, default=db.DEFAULT_WORKSPACE_ID,
                       help="which workspace's servers this account sees"
                            f" (default {db.DEFAULT_WORKSPACE_ID})")
    sub.add_parser("list", help="every account, with its state and live sessions")
    p_name = sub.add_parser(
        "name", help="set the name the account menu shows, empty text clears it")
    p_name.add_argument("email")
    p_name.add_argument("display_name")
    p_passwd = sub.add_parser(
        "passwd", help="set a new password and sign every session out")
    p_passwd.add_argument("email")
    p_disable = sub.add_parser(
        "disable", help="refuse this account and sign every session out")
    p_disable.add_argument("email")
    p_enable = sub.add_parser("enable", help="let a disabled account sign in again")
    p_enable.add_argument("email")
    p_erase = sub.add_parser(
        "erase", help="delete an account with its workspace, its servers and every"
                      " row about them. Without --yes it only says what would go")
    p_erase.add_argument("email")
    p_erase.add_argument("--yes", action="store_true",
                         help="delete it, then write the database file again")
    p_signout = sub.add_parser(
        "sign-out", help="revoke every live session of this account")
    p_signout.add_argument("email")

    p_admin = sub.add_parser("admin", help="who can see the service-wide numbers")
    sub_admin = p_admin.add_subparsers(dest="action", required=True)
    sub_admin.add_parser("list", help="every account that has the admin flag")
    for action, help_text in (("grant", "let this account see the Admin screen"),
                              ("revoke", "take the Admin screen away again")):
        p = sub_admin.add_parser(action, help=help_text)
        p.add_argument("email")

    p_link = sub.add_parser(
        "link", help="print a single-use URL that connects a provider sign-in")
    p_link.add_argument("email")
    p_link.add_argument("provider", choices=sorted(PROVIDERS))
    p_ids = sub.add_parser(
        "identities", help="which provider sign-ins this account has")
    p_ids.add_argument("email")
    p_unlink = sub.add_parser("unlink", help="remove a provider sign-in")
    p_unlink.add_argument("email")
    p_unlink.add_argument("provider", choices=sorted(PROVIDERS))
    p_prov = sub.add_parser(
        "providers", help="whether each provider is configured, and what to register")
    p_prov.add_argument("--check", action="store_true",
                        help="also fetch each provider's discovery document")

    p_mail = sub.add_parser(
        "mail", help="mail somebody a link that works once and expires")
    sub_mail = p_mail.add_subparsers(dest="kind", required=True)
    p_set = sub_mail.add_parser(
        "set-password", help="an account made here chooses its first password")
    p_set.add_argument("email")
    p_confirm = sub_mail.add_parser(
        "confirm", help="ask an account to confirm its address")
    p_confirm.add_argument("email")
    p_invite = sub_mail.add_parser(
        "invite", help="invite an address into a workspace")
    p_invite.add_argument("email")
    p_invite.add_argument("--from", dest="inviter", required=True,
                          help="the account doing the inviting")
    p_invite.add_argument("--workspace", type=int, default=None,
                          help="which workspace, the inviter's by default")
    for p in (p_set, p_confirm, p_invite):
        p.add_argument("--print-only", action="store_true",
                       help="print the URL and send no mail")

    p_2fa = sub.add_parser("2fa", help="two-factor authentication")
    sub_2fa = p_2fa.add_subparsers(dest="action", required=True)
    for action, help_text in (
            ("status", "whether two-factor is on, and how many recovery codes are left"),
            ("enable", "enrol an authenticator app, asks for a code to confirm"),
            ("disable", "turn two-factor off, which is the lockout path"),
            ("reset-codes", "throw away the recovery codes and print a fresh set")):
        p = sub_2fa.add_parser(action, help=help_text)
        p.add_argument("email")

    return parser


def main() -> int:
    args = build_parser().parse_args()

    # The environment file, then the database, or a refusal. `app/cli.py`
    # owns both and says why a missing database is refused rather than made.
    #
    # **This used to be a note printed just before making one**, and on
    # 2026-08-27 that note was printed on the production box and the command
    # went on to answer about the database it had just created. The note was
    # right and the shape was wrong.
    con = cli.open_database(args)
    try:
        db.init(con)
        accounts.init(con)
        identities.init(con)
        return run(con, args)
    finally:
        con.close()


def run(con, args) -> int:
    """The commands themselves, with the connection passed in so the tests can
    drive them against a temporary database."""
    if args.command == "providers":
        return run_providers(con, check=getattr(args, "check", False))

    if args.command == "add":
        try:
            password = read_password()
            accounts.create_user(con, args.email, password,
                                 workspace_id=args.workspace)
        except accounts.AccountError as exc:
            print(f"could not add {args.email}: {exc}", file=sys.stderr)
            return 1
        print(f"account {accounts.normalize_email(args.email)} created")
        return 0

    if args.command == "list":
        for user in accounts.list_users(con):
            state = "disabled" if user["disabled_at"] else "active"
            live = len(accounts.live_sessions(con, user["id"]))
            last = user["last_login_at"] or "never signed in"
            workspace = accounts.workspace_of(user)
            admin = " admin" if accounts.is_admin(user) else ""
            print(f"{user['email']:32} {state:9} workspace: {workspace:<3}"
                  f" sessions: {live:<3} last: {last}{admin}")
        return 0

    # Before the lookup below, because `admin list` names no account.
    if args.command == "admin" and args.action == "list":
        admins = [u for u in accounts.list_users(con) if accounts.is_admin(u)]
        if not admins:
            print("no account has the admin flag")
            return 0
        for user in admins:
            print(user["email"])
        return 0

    # Before the lookup below too: the erase says its own refusals, each in
    # one line that ends "nothing was changed" (`app/erase.py`).
    if args.command == "erase":
        return erase.run(con, args.email, yes=args.yes)

    # Before the lookup below as well: an invitation is about an address that
    # does not have an account yet, and refusing it for that would be refusing
    # the one thing it is for.
    if args.command == "mail":
        return run_mail(con, args)

    user = accounts.get_user_by_email(con, args.email)
    if user is None:
        # Every remaining command names an existing account, and an operator at
        # a terminal is not an enumeration surface, so this says plainly that
        # there is no such account rather than answering vaguely.
        print(f"no account for {args.email}", file=sys.stderr)
        return 1

    if args.command == "name":
        try:
            accounts.set_display_name(con, user["id"], args.display_name)
        except accounts.AccountError as exc:
            print(f"name not changed: {exc}", file=sys.stderr)
            return 1
        # Read back what was stored rather than echoing the argument, so the
        # trimmed value the menu will actually show is what the terminal says.
        stored = accounts.display_name_of(
            accounts.get_user_by_email(con, user["email"]))
        if stored:
            print(f"{user['email']} now shows as {stored}")
        else:
            print(f"{user['email']} now shows its email address")
        return 0

    if args.command == "passwd":
        try:
            accounts.set_password(con, user["id"], read_password())
        except accounts.AccountError as exc:
            print(f"password not changed: {exc}", file=sys.stderr)
            return 1
        # A password is changed when somebody thinks the old one is in the
        # wrong hands, and a session made with the old one must not outlive it.
        revoked = accounts.revoke_all_sessions(con, user["id"])
        print(f"password changed, {revoked} session(s) signed out")
        return 0

    if args.command == "disable":
        accounts.set_disabled(con, user["email"], True)
        revoked = accounts.revoke_all_sessions(con, user["id"])
        print(f"{user['email']} disabled, {revoked} session(s) signed out")
        return 0

    if args.command == "enable":
        accounts.set_disabled(con, user["email"], False)
        print(f"{user['email']} can sign in again")
        return 0

    if args.command == "sign-out":
        revoked = accounts.revoke_all_sessions(con, user["id"])
        print(f"{revoked} session(s) signed out")
        return 0

    if args.command == "admin":
        wanted = args.action == "grant"
        if accounts.is_admin(user) == wanted:
            # Say what is true rather than reporting a change nothing made. A
            # command that prints "granted" over an unchanged row is how an
            # operator ends up believing a second box is set up too.
            print(f"{user['email']} already"
                  f" {'has' if wanted else 'does not have'} the admin flag")
            return 0
        accounts.set_admin(con, user["email"], wanted)
        print(f"{user['email']} {'now has' if wanted else 'no longer has'}"
              " the admin flag")
        return 0

    if args.command == "2fa":
        return run_2fa(con, user, args.action)

    if args.command == "link":
        return run_link(con, user, args.provider)

    if args.command == "identities":
        rows = identities.for_user(con, user["id"])
        if not rows:
            print(f"{user['email']}: no provider sign-ins")
            return 0
        for row in rows:
            shown = row["email_shown"] or "no address"
            last = row["last_used_at"] or "never used"
            print(f"{row['provider']:12} {shown:32} last: {last}")
        return 0

    if args.command == "unlink":
        if identities.unlink(con, args.provider, user["id"]):
            print(f"{args.provider} sign-in removed for {user['email']}")
            return 0
        print(f"{user['email']} has no {args.provider} sign-in", file=sys.stderr)
        return 1

    return 1


def run_link(con, user, provider: str) -> int:
    """Mint the ticket and print the URL to open.

    **The URL is the secret, and it is printed once.** The row holds only its
    SHA-256, so it cannot be read back off the box, and it is spent the moment
    the browser opens it, whether or not the sign-in behind it succeeds.
    """
    base = oidc.base_url()
    ticket = identities.issue_ticket(con, user["id"], provider)
    minutes = int(identities.TICKET_TTL.total_seconds() // 60)
    print(f"\nOpen this once, in a browser, and sign in with {provider}:\n")
    if base:
        print(f"  {base}/login/link/{ticket}\n")
    else:
        # Better than printing a wrong URL. The path is right and the operator
        # knows their own address.
        print(f"  /login/link/{ticket}\n")
        print(f"  ({oidc.BASE_URL_ENV} is not set on this server, so the address"
              f" above is the path only.)\n")
    print(f"It works once and expires in {minutes} minutes. Whichever"
          f" {provider} account signs in behind it becomes the one that can")
    print(f"sign in as {user['email']}, so open it yourself rather than sending it on.\n")
    return 0


# Where a link points is `publicurl.base()`, the host the mails already print,
# so a link and the sentence around it cannot disagree about where the product
# lives.
_LINK_PATHS = {onetime.SET_PASSWORD: "/set-password", onetime.CONFIRM: "/confirm",
               onetime.INVITE: "/join"}


def _send_link(subject: str, body: str, html_body: str, to: str,
               url: str, print_only: bool) -> int:
    """Print the URL, and send the mail unless told not to.

    **The URL is printed either way.** A relay that is down or an address that
    bounces must not leave the operator with nothing: the link exists, it is
    the only copy, and handing it over another way is their call.
    """
    print(f"\n  {url}\n")
    if print_only:
        print("Nothing was sent. Pass the link on yourself.\n")
        return 0
    config = notify.config_from_env()
    if not config.host:
        print("No relay is configured on this box"
              " (WHICHPORTS_SMTP_HOST is unset), so nothing was sent.\n",
              file=sys.stderr)
        return 1
    one = replace(config, to=to, sender=config.sender or to)
    sent, reason = notify.send(subject, body, one, html_body)
    if not sent:
        print(f"The mail did not go out: {reason}\n", file=sys.stderr)
        return 1
    print(f"Sent to {to}.\n")
    return 0


def run_mail(con, args) -> int:
    """The four mails that carry a link, minus the reset, which the product
    asks for itself on its own page (`app/web_auth.py`, /forgot).

    Every one of them mints the link here and prints it, so an operator on the
    box can always see what was sent and can hand it over another way when the
    relay is not working.
    """
    onetime.init(con)
    email = accounts.normalize_email(args.email)

    if args.kind == "invite":
        inviter = accounts.get_user_by_email(con, accounts.normalize_email(args.inviter))
        if inviter is None:
            print(f"no account for {args.inviter}", file=sys.stderr)
            return 1
        if accounts.get_user_by_email(con, email) is not None:
            print(f"{email} already has an account", file=sys.stderr)
            return 1
        workspace_id = args.workspace or accounts.workspace_of(inviter)
        workspace = db.workspace_by_id(con, workspace_id)
        if workspace is None:
            print(f"no workspace {workspace_id}", file=sys.stderr)
            return 1
        token, _ = onetime.issue(con, onetime.INVITE, email,
                                 workspace_id=workspace_id,
                                 invited_by=inviter["email"])
        url = f"{publicurl.base()}{_LINK_PATHS[onetime.INVITE]}/{token}"
        # **No role.** The invitation says who invited and into which
        # workspace, and stops there: roles are not enforced anywhere in the
        # code yet, and a mail saying "as Admin" would be claiming a
        # permission level that does not exist (the accuracy rule). The
        # screen draws the role for when Members lands.
        subject, body, html_body = notify.format_invite(
            accounts.display_name_of(inviter), inviter["email"],
            workspace["name"], "", url)
        return _send_link(subject, body, html_body, email, url, args.print_only)

    user = accounts.get_user_by_email(con, email)
    if user is None:
        print(f"no account for {email}", file=sys.stderr)
        return 1

    if args.kind == "set-password":
        token, _ = onetime.issue(con, onetime.SET_PASSWORD, email, user_id=user["id"])
        url = f"{publicurl.base()}{_LINK_PATHS[onetime.SET_PASSWORD]}/{token}"
        subject, body, html_body = notify.format_account(email, url)
    else:
        token, _ = onetime.issue(con, onetime.CONFIRM, email, user_id=user["id"])
        url = f"{publicurl.base()}{_LINK_PATHS[onetime.CONFIRM]}/{token}"
        subject, body, html_body = notify.format_confirm(email, url)
    return _send_link(subject, body, html_body, email, url, args.print_only)


def run_2fa(con, user, action: str) -> int:
    """The two-factor subcommands. Split out so the enrolment conversation,
    which is the only interactive one here, is readable on its own."""
    on = accounts.totp_enabled(user)

    if action == "status":
        left = accounts.recovery_codes_remaining(con, user["id"])
        print(f"{user['email']}: two-factor {'on' if on else 'off'}"
              + (f", {left} recovery code(s) left" if on else ""))
        return 0

    if action == "disable":
        if not on:
            print(f"two-factor is already off for {user['email']}")
            return 0
        accounts.disable_totp(con, user["id"])
        print(f"two-factor off for {user['email']}, recovery codes destroyed")
        return 0

    if action == "reset-codes":
        if not on:
            print("two-factor is off, so there are no recovery codes",
                  file=sys.stderr)
            return 1
        _print_recovery_codes(accounts.reset_recovery_codes(con, user["id"]))
        return 0

    if action == "enable":
        return enrol(con, user)

    return 1


def enrol(con, user) -> int:
    """Show the secret, then refuse to turn anything on until a code proves an
    authenticator really holds it.

    **The confirming code is the point of this conversation.** Enabling on a
    secret nobody typed in correctly is how an operator locks themselves out of
    their own control plane, and this is the one place that can be prevented.
    """
    try:
        secret = accounts.begin_totp_enrollment(con, user["id"])
    except accounts.AccountError as exc:
        print(f"could not start enrolment: {exc}", file=sys.stderr)
        return 1

    print(f"\nAdd this to an authenticator app for {user['email']}.\n")
    print(f"  key: {totp.format_secret_groups(secret)}")
    print(f"  uri: {totp.otpauth_uri(secret, user['email'])}\n")
    print("Type the key by hand, or paste the uri if the app takes one.\n")

    try:
        code = input("code from the app: ")
    except (EOFError, KeyboardInterrupt):
        print("\nnothing was turned on", file=sys.stderr)
        return 1

    try:
        codes = accounts.confirm_totp_enrollment(
            con, user["id"], code, at_time=time.time())
    except accounts.AccountError as exc:
        # The secret stays on the row, unconfirmed and inert, so running
        # `2fa enable` again just mints a new one.
        print(f"two-factor is still off: {exc}", file=sys.stderr)
        return 1

    print(f"\ntwo-factor is on for {user['email']}")
    _print_recovery_codes(codes)
    return 0


def _print_recovery_codes(codes) -> None:
    """The only moment these exist in readable form. The database holds scrypt
    hashes, so there is no second chance to read them and no support path that
    could hand them over."""
    print("\nRecovery codes. Each one works once, and this is the only time")
    print("they are shown. Put them somewhere that is not this server.\n")
    for code in codes:
        print(f"  {code}")
    print()


# The entry point stays at the very bottom, after every function it can reach.
# Anything defined below it is not defined yet when it runs.


def run_providers(con, check: bool = False) -> int:
    """Say, for each provider, whether this process can actually use it.

    **This command exists because its absence cost a real afternoon.** The
    credentials were written into `/etc/whichports/controlplane.env`, the ingest
    unit had no `EnvironmentFile=` line, so the file was read by nothing. The
    only symptom was a login page with no buttons on it, which looks exactly
    like a provider that was never configured. Every check below is a question
    somebody had to answer by reading source code that day.

    **No secret is printed, ever.** A secret is reported as set or not set, and
    the client id is shown because it is not a secret: it travels in the
    authorization URL in the operator's own browser.
    """
    ok = True
    base = oidc.base_url()
    print(f"{oidc.BASE_URL_ENV:34} {base or 'NOT SET'}")
    if not base:
        # Nothing else can be right without it, and every provider below will
        # say so, so the reason is given once here.
        print("  Without it there is nowhere for a provider to send the browser")
        print("  back to, so every provider below is off whatever else is set.")
        ok = False
    print()

    for name in sorted(PROVIDERS):
        provider = PROVIDERS[name]
        client_id = provider.client_id()
        secret_set = provider.client_secret() is not None
        ready = oidc.is_ready(provider)
        print(f"{provider.label}")
        print(f"  {provider.env_prefix + '_CLIENT_ID':32} "
              f"{client_id or 'NOT SET'}")
        print(f"  {provider.env_prefix + '_CLIENT_SECRET':32} "
              f"{'set' if secret_set else 'NOT SET'}")
        for extra, value in provider.extra_env().items():
            print(f"  {extra:32} {value or 'NOT SET'}")

        if base:
            # The single most common way this goes wrong, so it is printed
            # whether or not everything else passed: both providers match the
            # redirect URI exactly, and a trailing slash or a capital letter is
            # a refusal at the consent screen rather than here.
            print(f"  {'register this redirect URI':32} "
                  f"{base}/login/{provider.name}/callback")

        if ready:
            print(f"  {'on the login page':32} yes")
        else:
            print(f"  {'on the login page':32} NO, and /login/"
                  f"{provider.name} answers 404")
            ok = False

        if check and ready:
            # The one thing that needs the network, so it is behind a flag. It
            # proves this box can reach the provider and that the document it
            # answers with is usable, which is everything the sign-in needs
            # before a browser is involved.
            try:
                document = oidc.discovery(provider)
            except oidc.OIDCError as exc:
                print(f"  {'discovery':32} FAILED, {exc}")
                ok = False
            else:
                print(f"  {'discovery':32} ok, "
                      f"issuer {document.get('issuer')}")

        linked = con.execute(
            "SELECT u.email FROM oidc_identities i JOIN users u ON u.id = i.user_id"
            " WHERE i.provider = ?", (provider.name,)).fetchall()
        if linked:
            for row in linked:
                print(f"  {'connected to':32} {row['email']}")
        else:
            print(f"  {'connected to':32} nobody yet, run"
                  f" `users_cli link <email> {provider.name}`")
        print()

    if not check:
        print("Add --check to also fetch each provider's discovery document,")
        print("which is the only step here that needs the network.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
