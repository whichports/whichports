"""Every command opens the real database, or refuses and says how.

    python -m pytest tests/test_cli_database.py

Because the owner reads every diff but has said he cannot be relied on to catch a
subtle bug in review, these tests are the review. The one
that carries the whole argument is
`test_no_entry_point_makes_a_database_by_accident`: it is parametrised over
every `main` in the package, found by walking the tree rather than by a list
somebody maintains, so a command added later is covered the day it is added.

The failure being closed here happened twice. On 2026-08-23 every command run
from a shell on the box opened a database nobody meant, because a shell does
not inherit a service's environment and `db.DEFAULT_DB` is a relative path.
`app/envfile.py` fixed the reading of the environment file and reached exactly
one of the eleven commands, and the units turned out to set `WHICHPORTS_DB`
with `Environment=` rather than in that file, so even that one still opened the
wrong database. On 2026-08-27 `users_cli admin grant` on the production box
made `/srv/controlplane/whichports.db` and reported that the account did not
exist.
"""

import argparse
import importlib
import pathlib
import pkgutil

import pytest

import app as app_package
from app import cli, db, envfile


def entry_points():
    """Every module in `app` with a `main`, found by walking the package.

    A hand-written list is the thing that went wrong here in the first place:
    the 2026-08-23 fix was applied to the one command somebody thought of.
    """
    found = []
    for info in pkgutil.iter_modules(app_package.__path__):
        module = importlib.import_module(f"app.{info.name}")
        if callable(getattr(module, "main", None)):
            found.append(info.name)
    return sorted(found)


def test_the_walk_finds_the_commands_we_know_about():
    """A guard on the guard. If the walk started returning nothing, every test
    below would pass by covering no command at all."""
    names = entry_points()
    for expected in ("users_cli", "hosts_cli", "join_cli", "intent_cli",
                     "authz_cli", "prober_cli", "sweep_cli"):
        assert expected in names
    assert len(names) >= 11


# =========================== nothing creates a database as a side effect

@pytest.mark.parametrize("name", entry_points())
def test_no_entry_point_makes_a_database_by_accident(name, tmp_path,
                                                     monkeypatch):
    """Whatever this command does, running it against a path that is not there
    must leave that path not there.

    Driven at `cli.open_database` rather than through each `main`, because the
    eleven parsers want eleven different argument lists and what is being
    checked is the one gate they all pass through. That they all pass through
    it is `test_every_entry_point_goes_through_the_gate` below.
    """
    absent = tmp_path / f"{name}.db"
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(tmp_path / "absent.env"))
    monkeypatch.setenv(db.DB_ENV, str(absent))
    with pytest.raises(SystemExit):
        cli.open_database(argparse.Namespace())
    assert not absent.exists()


@pytest.mark.parametrize("name", entry_points())
def test_every_entry_point_goes_through_the_gate(name):
    """No `main` calls `db.connect` directly.

    Read from the source rather than by running anything, because a command
    that reaches the database on some branch a test did not take is exactly the
    case that got missed last time. `db.connect` is fine everywhere else in the
    package: it is the entry points that have to resolve the environment first.
    """
    source = (pathlib.Path(app_package.__path__[0]) / f"{name}.py").read_text()
    body = source[source.index("def main("):]
    assert "db.connect(" not in body, (
        f"app/{name}.py reaches db.connect() from main(). Use"
        f" cli.open_database(args), which reads the environment file first and"
        f" refuses to invent a database (app/cli.py)")


# ==================================================== what the refusal says

def test_the_refusal_names_the_path_it_resolved(tmp_path, monkeypatch):
    """The whole failure is that the path it opened and the path somebody meant
    were different and nobody could see it. So it prints the one it resolved."""
    absent = tmp_path / "not-here.db"
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(tmp_path / "absent.env"))
    monkeypatch.setenv(db.DB_ENV, str(absent))
    with pytest.raises(SystemExit) as refused:
        cli.open_database()
    assert str(absent) in str(refused.value)


def test_the_refusal_names_both_ways_to_fix_it():
    message = cli.refusal(pathlib.Path("/somewhere/whichports.db"))
    assert db.DB_ENV in message
    assert envfile.DEFAULT_PATH in message
    assert cli.CREATE_FLAG in message


def test_the_refusal_states_no_production_path():
    """`app/cli.py` says why: the box's path is owned by the unit files and by
    ops/RUNBOOK.md, and a second copy in the application is a copy that goes
    stale on the day it matters."""
    message = cli.refusal(pathlib.Path("/somewhere/whichports.db"))
    assert "/var/lib" not in message
    assert "/srv/" not in message


# =============================================== the environment file first

def test_the_environment_file_decides_when_nothing_else_has(tmp_path,
                                                            monkeypatch):
    chosen = tmp_path / "from-the-file.db"
    db.connect(str(chosen)).close()
    envpath = tmp_path / "cp.env"
    envpath.write_text(f"{db.DB_ENV}={chosen}\n")
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(envpath))
    monkeypatch.delenv(db.DB_ENV, raising=False)
    assert cli.resolve() == chosen


def test_a_variable_already_set_still_wins(tmp_path, monkeypatch):
    """Whoever typed `WHICHPORTS_DB=... command` asked for that one, and every
    test in this suite depends on it."""
    envpath = tmp_path / "cp.env"
    envpath.write_text(f"{db.DB_ENV}={tmp_path / 'from-the-file.db'}\n")
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(envpath))
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "typed.db"))
    assert cli.resolve() == tmp_path / "typed.db"


def test_a_missing_environment_file_is_not_an_error(tmp_path, monkeypatch):
    """On a laptop there is no such file and that is the ordinary case."""
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(tmp_path / "nothing.env"))
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "x.db"))
    assert cli.resolve() == tmp_path / "x.db"


# A name nothing in the package reads, on purpose. `envfile.load` writes
# straight into `os.environ`, which monkeypatch cannot undo for a variable that
# was not set to begin with, so an earlier version of this test set
# WHICHPORTS_HETZNER_TOKEN and leaked it into every test that ran after it.
# tests/test_sweep_cli.py::test_no_token_fetches_nothing failed three files
# later, which is the whole reason the suite runs in one process.
LEAK_SAFE_VAR = "WHICHPORTS_ENVFILE_PROBE"


def test_load_environment_can_be_called_twice(tmp_path, monkeypatch):
    """`hetzner_cli` calls it before it touches the database, and
    `open_database` calls it again. The second call must change nothing."""
    import os
    envpath = tmp_path / "cp.env"
    envpath.write_text(f"{LEAK_SAFE_VAR}=from-the-file\n")
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(envpath))
    os.environ.pop(LEAK_SAFE_VAR, None)
    try:
        cli.load_environment()
        assert os.environ[LEAK_SAFE_VAR] == "from-the-file"
        cli.load_environment()
        assert os.environ[LEAK_SAFE_VAR] == "from-the-file"
    finally:
        os.environ.pop(LEAK_SAFE_VAR, None)


# ================================================================ the flag

def test_the_flag_lets_a_first_run_make_one(tmp_path, monkeypatch):
    fresh = tmp_path / "fresh.db"
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(tmp_path / "absent.env"))
    monkeypatch.setenv(db.DB_ENV, str(fresh))
    con = cli.open_database(argparse.Namespace(create_database=True))
    con.close()
    assert fresh.exists()


def test_a_parser_without_the_flag_answers_false_rather_than_raising():
    """Nine of the eleven parsers do not offer it, and reading an attribute
    that is not there would turn every one of them into a crash."""
    assert cli.wants_create(argparse.Namespace()) is False
    assert cli.wants_create(None) is False


@pytest.mark.parametrize("module_name", ["users_cli", "hosts_cli"])
def test_the_two_bootstrapping_commands_offer_the_flag(module_name):
    module = importlib.import_module(f"app.{module_name}")
    parser = argparse.ArgumentParser()
    cli.add_create_flag(parser)
    # The flag exists on the real parser too, which is what a person types.
    source = (pathlib.Path(app_package.__path__[0]) / f"{module_name}.py").read_text()
    assert "cli.add_create_flag(parser)" in source
    assert callable(module.main)


@pytest.mark.parametrize("module_name", [
    "join_cli", "intent_cli", "authz_cli", "silence_cli", "channels_cli",
    "prober_cli", "scan_cli", "sweep_cli", "hetzner_cli"])
def test_the_other_nine_do_not_offer_it(module_name):
    """`join_cli --create-database` would be meaningless: nothing reads a
    finding out of a database it just made."""
    source = (pathlib.Path(app_package.__path__[0]) / f"{module_name}.py").read_text()
    assert "add_create_flag" not in source


# ============================ the one that would have caught 2026-08-27

def test_a_command_that_writes_refuses_rather_than_writing_nowhere(tmp_path,
                                                                   monkeypatch):
    """`intent_cli declare` and the authz commands write. The 2026-08-27 case
    was a read, which merely gave a wrong answer. The same mistake on a write
    is work that looks like it succeeded and reached no product."""
    from app import intent_cli
    absent = tmp_path / "nowhere.db"
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(tmp_path / "absent.env"))
    monkeypatch.setenv(db.DB_ENV, str(absent))
    with pytest.raises(SystemExit):
        intent_cli.main(["declare", "--host", "almabox", "--port", "22",
                         "--protocol", "tcp", "--expose", "internet"])
    assert not absent.exists()
