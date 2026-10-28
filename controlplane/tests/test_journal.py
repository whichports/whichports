"""The application's info lines reach the journal, and what a host chose
cannot forge one.

    python -m pytest tests/test_journal.py

Found on 2026-10-02: after the beta list was turned on, nobody could read
from the journal whether the operator's mail had left. uvicorn configures its
own three loggers and leaves the root one alone, so a line this application
wrote at info level went nowhere (`app/journal.py`).
"""
import io
import logging
import pathlib
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from app import db, ingest, journal, store


@pytest.fixture()
def clean_loggers():
    """The handlers and levels of the two trees, put back afterwards, so a
    test that configures them does not change what every later test prints."""
    before = {name: (logging.getLogger(name).level,
                     list(logging.getLogger(name).handlers))
              for name in journal.TREES}
    yield
    for name, (level, handlers) in before.items():
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.handlers[:] = handlers


# What the service is on the box: uvicorn's own logging configuration, then
# this application. Run in a process of its own, because the logging state of
# a test run is pytest's and proves nothing about a server.
UNDER_UVICORN = """
import logging, logging.config, sys
import uvicorn.config
logging.config.dictConfig(uvicorn.config.LOGGING_CONFIG)
from app import journal
if sys.argv[1] == "configured":
    journal.configure()
    journal.configure()
logging.getLogger("app.betasignup_routes").info("beta signup: mail sent")
logging.getLogger("whichports.notify").info("an info line from notify")
logging.getLogger("app.ingest").warning("a warning from the ingest")
logging.getLogger("app.ingest").debug("a debug line")
logging.getLogger("somebody.elses").info("another library's info line")
"""


def under_uvicorn(mode: str) -> list:
    # From the control plane's own directory, which is where `app` is found,
    # wherever the suite itself was started.
    done = subprocess.run([sys.executable, "-c", UNDER_UVICORN, mode],
                          cwd=pathlib.Path(__file__).resolve().parents[1],
                          capture_output=True, text=True, check=True)
    assert done.stdout == ""
    return done.stderr.splitlines()


def test_before_this_an_info_line_went_nowhere_and_a_warning_showed():
    """The fault, held as it was, so this file fails if the reason for it
    ever stops being true and the module can then go."""
    assert under_uvicorn("as it was") == ["a warning from the ingest"]


def test_an_info_line_from_either_tree_reaches_stderr_once():
    assert under_uvicorn("configured") == [
        "beta signup: mail sent",
        "an info line from notify",
        "a warning from the ingest",
    ], "each line once, a debug line and another library's stay out"


def test_the_service_configures_it_when_it_starts_and_not_at_import(clean_loggers):
    def ours(name):
        return [h for h in logging.getLogger(name).handlers
                if getattr(h, "whichports_journal", False)]

    for name in journal.TREES:
        assert ours(name) == [], "importing app.ingest added nothing"
    with TestClient(ingest.app):
        for name in journal.TREES:
            assert len(ours(name)) == 1
            assert logging.getLogger(name).isEnabledFor(logging.INFO)
    with TestClient(ingest.app):
        for name in journal.TREES:
            assert len(ours(name)) == 1, "a second start adds no second handler"


def test_a_line_is_the_message_and_nothing_else(clean_loggers):
    stream = io.StringIO()
    journal.configure(stream)
    logging.getLogger("app.anything").info("no authorisation recorded for host %s: %s",
                                           7, "the host is revoked")
    assert stream.getvalue() == "no authorisation recorded for host 7: the host is revoked\n"


def test_every_logger_the_application_makes_is_in_one_of_the_two_trees():
    """A module that named its logger something else would be quiet again."""
    import re
    app = pathlib.Path(ingest.__file__).parent
    for path in sorted(app.glob("*.py")):
        if path.name == "journal.py":
            continue  # it asks for the two trees by name, from a variable
        for name in re.findall(r"logging\.getLogger\(([^)]*)\)", path.read_text()):
            assert name == "__name__" or name.strip("\"'").startswith("whichports."), (
                f"{path.name} makes a logger named {name}, outside {journal.TREES}")


# ------------------------------------------- what a host chose, in a line
#
# The lines that say why a report authorised nothing name the host. A name
# that could hold a line break would let a host write a line of its own into
# the journal. Every door a name comes in by refuses or replaces one.

FORGED = ["web\n2026-10-02 forged line", "we\rb", "web\x1b[31m", "web\x00",
          "web\u2028x", "web 01", "web\t01"]


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(tmp_path / "t.db")
    db.init(connection)
    yield connection
    connection.close()


@pytest.mark.parametrize("name", FORGED)
def test_a_name_with_a_control_character_is_refused_when_a_host_is_added(con, name):
    with pytest.raises(ValueError):
        store.add_host(con, name)


@pytest.mark.parametrize("hostname", FORGED + ["WEB\n", "\nweb", "web\n\n"])
def test_a_hostname_from_a_document_is_cleaned_before_it_becomes_a_name(con, hostname):
    host_id, _credential = store.add_host(con)
    store.auto_name_from_hostname(con, host_id, hostname)
    name = con.execute("SELECT name FROM hosts WHERE id = ?", (host_id,)).fetchone()["name"]
    assert store.NAME_RE.fullmatch(name), repr(name)
    assert name.isprintable() and "\n" not in name


def test_a_trailing_line_break_does_not_ride_in_on_the_end_of_a_name(con):
    """`$` in a pattern also matches before a final line break, so the name
    rule alone would take "web" followed by one. The name is stripped first,
    and what is stored is the name without it."""
    assert store.NAME_RE.match("web\n"), "which is why the strip matters"
    host_id, _credential = store.add_host(con, "web\n")
    stored = con.execute("SELECT name FROM hosts WHERE id = ?", (host_id,)).fetchone()["name"]
    assert stored == "web"
