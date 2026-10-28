"""Reading the file the units read.

    python -m pytest tests/test_envfile.py

This module exists because of a specific failure and the tests are shaped by it.
On 2026-08-23 the credentials were in `/etc/whichports/controlplane.env`, the
ingest unit read them and every command run from a shell did not. `WHICHPORTS_DB`
was among them, `db.DEFAULT_DB` is a relative path, so each command quietly made
a second database beside the working directory and reported truthfully on that
one. `users_cli list` said there were no accounts, which was true of the file it
had just created and false of the product.

The property that matters most here: **a variable already set is never
overridden**, because the tests set `WHICHPORTS_DB` themselves and a file on the
box must not be able to take that decision away from them.
"""

import pytest

from app import envfile


# ------------------------------------------------------------------ parsing

def test_the_ordinary_shape():
    parsed = envfile.parse("A=1\nB=two\n")
    assert parsed == {"A": "1", "B": "two"}


def test_comments_and_blank_lines_are_skipped():
    parsed = envfile.parse("# a note\n\nA=1\n   \n# another\nB=2\n")
    assert parsed == {"A": "1", "B": "2"}


def test_an_export_prefix_is_tolerated():
    """Somebody will paste a line from their shell profile."""
    assert envfile.parse("export A=1\n") == {"A": "1"}


@pytest.mark.parametrize("line,expected", [
    ('A="quoted"', "quoted"),
    ("A='quoted'", "quoted"),
    ('A=unquoted', "unquoted"),
    ('A="with spaces inside"', "with spaces inside"),
    ('A=', ""),
])
def test_values_and_their_quoting(line, expected):
    assert envfile.parse(line)["A"] == expected


def test_only_one_pair_of_quotes_is_stripped():
    """A client secret can genuinely contain a quote, and eating it would make
    a credential that is wrong in a way nothing reports."""
    assert envfile.parse("""A=""doubled"" """.strip())["A"] == '"doubled"'


def test_a_value_containing_an_equals_sign_survives():
    """Base64 and Entra secrets both do this."""
    assert envfile.parse("A=abc=def==")["A"] == "abc=def=="


@pytest.mark.parametrize("junk", ["novalue", "=novalue", "   ", "#A=1"])
def test_a_line_it_cannot_read_is_skipped_rather_than_raising(junk):
    """A command refusing to start over one stray line is worse than the line
    being ignored."""
    parsed = envfile.parse(f"{junk}\nGOOD=1\n")
    assert parsed.get("GOOD") == "1"


# ------------------------------------------------------------------ loading

def test_load_sets_what_is_missing(tmp_path):
    path = tmp_path / "cp.env"
    path.write_text("WHICHPORTS_TEST_ONE=1\nWHICHPORTS_TEST_TWO=2\n")
    environ = {}
    assert envfile.load(str(path), environ=environ) == [
        "WHICHPORTS_TEST_ONE", "WHICHPORTS_TEST_TWO"]
    assert environ["WHICHPORTS_TEST_ONE"] == "1"


def test_load_never_overrides_something_already_set(tmp_path):
    """**The load-bearing one.** The tests set WHICHPORTS_DB themselves, and a
    file on the box must not be able to take that decision away from them, or
    every suite would start writing to the production path."""
    path = tmp_path / "cp.env"
    path.write_text("WHICHPORTS_DB=/var/lib/whichports-controlplane/whichports.db\n")
    environ = {"WHICHPORTS_DB": "/tmp/the-test-database.db"}
    applied = envfile.load(str(path), environ=environ)
    assert applied == []
    assert environ["WHICHPORTS_DB"] == "/tmp/the-test-database.db"


def test_a_missing_file_is_not_an_error(tmp_path):
    """On a laptop there is no such file, and that is the ordinary case."""
    environ = {}
    assert envfile.load(str(tmp_path / "absent.env"), environ=environ) == []
    assert environ == {}


def test_a_directory_where_the_file_should_be_is_not_an_error(tmp_path):
    (tmp_path / "cp.env").mkdir()
    assert envfile.load(str(tmp_path / "cp.env"), environ={}) == []


def test_an_unreadable_file_is_not_an_error(tmp_path):
    """The real file is mode 640 root:deploy, so a command run as somebody else
    cannot read it and must carry on rather than fall over."""
    path = tmp_path / "cp.env"
    path.write_text("A=1\n")
    path.chmod(0o000)
    try:
        assert envfile.load(str(path), environ={}) == []
    finally:
        path.chmod(0o600)


def test_the_default_path_is_the_one_the_units_name():
    """One constant, so the unit file and this agree by construction rather
    than by somebody remembering to change both."""
    assert envfile.DEFAULT_PATH == "/etc/whichports/controlplane.env"
