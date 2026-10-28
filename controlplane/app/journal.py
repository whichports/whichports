"""The lines this application writes at info level reach the journal.

uvicorn configures three loggers of its own, `uvicorn`, `uvicorn.error` and
`uvicorn.access`, and leaves the root logger alone
(`uvicorn.config.LOGGING_CONFIG`, read 2026-10-02 at 0.52.2). A record that
no handler takes is then shown by Python only when it is a warning or worse:
`logging.lastResort` is "a handler of last resort", "configured with a level
of WARNING" (Python's logging documentation). So a warning from this
application showed in the journal and every info line went nowhere.

That was found on 2026-10-02, the day the beta list was turned on: after a
join, nobody could read from the journal whether the operator's mail had
left, because "beta signup: mail sent" is an info line. The same was true of
the lines that say why a report authorised no address.

`configure()` gives the application's own loggers one handler on stderr,
which is the journal under systemd and the container's log under Compose. It
runs when the service starts and not when a module is imported, so a command
line tool that imports the application stays as quiet as it was.

**This decides where a line goes, never what is in it.** What a line may
hold is decided where it is written. The journal is on the operator's own
box, beside the database that already holds every address in it, so a
sentence for a person may name an address or a host. A mail address is the
exception and is never logged: the beta list's lines carry an outcome and
nothing else (`app/betasignup_routes.py`).
"""
import logging

# The two names this application's loggers start with: `app.` for the ones
# made with `logging.getLogger(__name__)`, and `whichports.` for the ones
# named by hand (alerts, notify, webhook).
TREES = ("app", "whichports")

# The message alone, which is how a warning already looked in the journal
# when Python's handler of last resort wrote it. journald adds the time.
FORMAT = "%(message)s"

_MARK = "whichports_journal"


def configure(stream=None) -> None:
    """Give each of the application's logger trees one handler on stderr, at
    info level. Calling it again adds nothing. `stream` is for tests."""
    for name in TREES:
        logger = logging.getLogger(name)
        if logger.getEffectiveLevel() > logging.INFO:
            logger.setLevel(logging.INFO)
        if any(getattr(handler, _MARK, False) for handler in logger.handlers):
            continue
        handler = logging.StreamHandler(stream)
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter(FORMAT))
        setattr(handler, _MARK, True)
        logger.addHandler(handler)
