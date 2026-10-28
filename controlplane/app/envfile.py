"""Read the file the units read, so a command sees what the service sees.

**This exists because of one afternoon on 2026-08-23.** The credentials were in
`/etc/whichports/controlplane.env`, the ingest unit read them through
`EnvironmentFile=`, and every command run from a shell did not, because a shell
does not inherit a service's environment. Two things followed, and the second
was worse than the first:

  - `users_cli providers` reported every variable as NOT SET while the running
    service had them all, so the diagnostic command confidently said the
    opposite of the truth.
  - `WHICHPORTS_DB` was unset too, and `db.DEFAULT_DB` is a relative path. So
    every command **silently created a second database** beside the working
    directory and worked in that one. `users_cli list` then said there were no
    accounts, which was true of the file it had just made and false of the
    product. An account created that way went nowhere.

The second is the one worth naming: a wrong answer that looks like a right
answer. Nothing errored, nothing was logged, and the only clue was a stray file
nobody looks at.

**Nothing here overrides a variable that is already set.** A value in the real
environment wins, because that is what the person running the command asked
for, and because the tests set `WHICHPORTS_DB` themselves and must keep
deciding.

The format is the subset systemd's `EnvironmentFile=` uses that we actually
write: `KEY=VALUE` one per line, `#` comments, blank lines, and optional
surrounding quotes on the value. Anything it cannot parse is skipped rather
than raising, because a command refusing to start over a stray line in a
config file is worse than the line being ignored.
"""

import os
import pathlib

# Where the units point their `EnvironmentFile=` at. One constant, so the unit
# file and this agree by construction rather than by somebody remembering.
DEFAULT_PATH = "/etc/whichports/controlplane.env"


def parse(text: str) -> dict:
    """The KEY=VALUE pairs in an environment file, as a dict."""
    found = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key:
            continue
        value = value.strip()
        # A value may be quoted. Strip one matching pair, and only one, so a
        # secret that genuinely contains a quote survives.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        found[key] = value
    return found


def load(path: str | None = None, environ=None) -> list[str]:
    """Put the file's variables into the environment and return the names set.

    A missing or unreadable file is not an error and sets nothing: on a laptop
    there is no such file, and that is the ordinary case rather than a fault.
    """
    environ = os.environ if environ is None else environ
    target = pathlib.Path(path or DEFAULT_PATH)
    try:
        text = target.read_text()
    except OSError:
        # Missing, or there but not readable by this user. Either way there is
        # nothing to load and the caller carries on with what it already has.
        return []
    applied = []
    for key, value in parse(text).items():
        if key in environ:
            # Already set, so the person running this decided. Never override.
            continue
        environ[key] = value
        applied.append(key)
    return sorted(applied)
