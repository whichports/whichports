"""What a command opens, and what it refuses to invent.

## The afternoon this is named after, and the one it did not fix

`app/envfile.py` was written on 2026-08-23 because a shell does not inherit a
service's environment, so every command run by hand saw none of the
configuration the running units see. Its docstring names the worse of the two
consequences: `WHICHPORTS_DB` was unset, `db.DEFAULT_DB` is a *relative* path,
so a command silently made a second database beside the working directory and
answered questions about that one. Nothing errored. Nothing was logged.

**That fix reached exactly one command.** `app/users_cli.py` called
`envfile.load()` and printed a note. The other ten command line entry points in
this package called `db.connect()` and said nothing at all, and the units set
`WHICHPORTS_DB` with `Environment=` rather than in the environment file, so the
file `envfile.load()` reads never carried it either. On 2026-08-27 that came
back exactly as predicted: `users_cli admin grant` on the production box made
`/srv/controlplane/whichports.db`, looked for the account in it, and said there
was no such account. There was. It was in the real database.

The note is why it was caught in a minute rather than a week, and a note is
still the wrong shape for this. Anything that reads answers a question about
nothing, and `intent_cli declare` and `authz_cli` **write**, so the same
mistake there is work that appears to succeed and reaches no product.

## So: refuse, and say the two things that fix it

**No command here creates a database as a side effect of being run.** A path
that is not there is a refusal naming the resolved path, the variable, and the
file. Bootstrapping is a real thing that happens once, so the two commands that
genuinely do it, `users_cli` and `hosts_cli`, take `--create-database`. The
other nine never legitimately create one and have no flag to add.

This is not a warning turned into an error for tidiness. The reverse, an error
downgraded to a warning, is what this project forbids. It is a wrong answer turned into no answer.

## What this deliberately does not do

**It states no production path.** The refusal names `WHICHPORTS_DB` and
`/etc/whichports/controlplane.env` and stops, the same as `envfile.py` does.
Where the database lives on the box is written in the unit files and in
`ops/RUNBOOK.md`, and a second copy in the application would be a copy that
goes stale on the day it matters.

**It does not touch systemd.** The units keep setting `WHICHPORTS_DB` with
`Environment=`. Whether an `EnvironmentFile=` value would override one of those
is a question this change does not need answered, so it does not answer it.
`ops/RUNBOOK.md` says to keep the two the same value and why.
"""

import pathlib

from . import db, envfile

# The flag the two bootstrapping commands carry. One constant, because the
# parser that offers it and the code that reads it are in different files.
CREATE_FLAG = "--create-database"
CREATE_DEST = "create_database"


def refusal(path) -> str:
    """What to print instead of making a database nobody asked for.

    It names the path it resolved rather than the path it wanted, because the
    whole failure is that those two are different and nobody could see it.
    """
    return (
        f"refusing to work on a database that is not there:\n"
        f"  {path}\n"
        f"\n"
        f"Nothing here creates one as a side effect, because a command that\n"
        f"quietly makes a second database answers about the wrong one.\n"
        f"\n"
        f"If you meant a database that already exists, point {db.DB_ENV} at it:\n"
        f"  {db.DB_ENV}=/path/to/whichports.db <this command>\n"
        f"or put that line in {envfile.DEFAULT_PATH}, which every command\n"
        f"here reads before it does anything else.\n"
        f"\n"
        f"If you really are starting a new one, pass {CREATE_FLAG}."
    )


def add_create_flag(parser) -> None:
    """Offer `--create-database` on a parser. Only the two commands that
    bootstrap get this: making an account and adding the first host are the
    two things somebody does before there is a database."""
    parser.add_argument(
        CREATE_FLAG, action="store_true",
        help="make the database if it is not there. Without this a missing"
             " database is a refusal, not a new file")


def wants_create(args) -> bool:
    """Whether this invocation may create a database.

    `getattr` rather than an attribute read, because nine of the eleven
    parsers do not offer the flag and must answer False rather than raise.
    """
    return bool(getattr(args, CREATE_DEST, False))


def load_environment() -> list:
    """Read the file the units read, before anything asks the environment a
    question.

    `open_database` does this on its own, so most commands never call it. It is
    separate for the commands that read configuration *before* they touch the
    database: `hetzner_cli` reads the provider token, and without this it
    reported "not configured" on a box where the running service had the token
    all along, which is the first of the two failures `app/envfile.py` names.

    Safe to call twice. `envfile.load` never overrides a variable that is
    already set, so the second call changes nothing.
    """
    return envfile.load()


def resolve() -> pathlib.Path:
    """Read the environment file, then say which database this command means.

    The file is read first and every time, so a command sees what the units
    see. `envfile.load` never overrides a variable that is already set, so
    `WHICHPORTS_DB=... some-command` on the command line still wins, which is
    what somebody typing it asked for.
    """
    envfile.load()
    return pathlib.Path(db.db_path())


def open_database(args=None, create: bool = False):
    """The connection every command in this package starts from.

    Raises SystemExit with `refusal` when the database is not there and this
    invocation was not told it may make one. SystemExit rather than a custom
    error, because every caller is a `main` whose only honest response is to
    print this and stop.
    """
    path = resolve()
    if not path.exists() and not (create or wants_create(args)):
        raise SystemExit(refusal(path))
    return db.connect()
