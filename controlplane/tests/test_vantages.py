"""The vantage registry: rows saying where the outside view is taken from.

Nothing here probes. These pin what the registry accepts, what it refuses at
the door, and the one property the whole thing rests on: no column can hold a
credential.
"""
import sqlite3
from datetime import datetime, timezone

import pytest

from app import db, vantages, vantages_cli

V4 = "78.141.210.130"
V6 = "2a05:f480:1400:2015:5400:6ff:fe94:df5"
OTHER_V4 = "185.199.108.154"


@pytest.fixture()
def con():
    connection = db.connect(":memory:")
    db.init(connection)
    vantages.init(connection)
    yield connection
    connection.close()


# ------------------------------------------------------------------ schema


def test_init_is_idempotent(con):
    vantages.init(con)
    vantages.init(con)
    assert vantages.list_all(con) == []


def test_no_column_can_hold_a_credential(con):
    """The registry is read by the sweep, the metrics and the admin numbers.
    A column that could hold a key or a password would be a column all three
    could leak, so there is none, and this pins the names."""
    for table in ("vantages", "vantage_addresses"):
        columns = [row[1] for row in con.execute(f"PRAGMA table_info({table})")]
        for column in columns:
            assert not any(word in column.lower() for word in
                           ("key", "secret", "password", "token", "credential"))


def test_table_exists_answers_before_and_after_init():
    bare = db.connect(":memory:")
    db.init(bare)
    assert vantages.table_exists(bare) is False
    vantages.init(bare)
    assert vantages.table_exists(bare) is True


# --------------------------------------------------------------------- add


def test_add_records_name_destination_and_addresses(con):
    now = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)
    vantage = vantages.add(con, "probe1", "root@" + V4, [V4, V6], now=now)
    assert vantage.name == "probe1"
    assert vantage.destination == "root@" + V4
    assert vantage.enabled is True
    assert vantage.added_at == now.isoformat()
    assert vantage.addresses == (V4, V6)


def test_an_address_is_stored_canonical(con):
    vantage = vantages.add(con, "p", "root@h", [V6.upper()])
    assert vantage.addresses == (V6,)


def test_duplicate_addresses_in_one_add_are_one_row(con):
    vantage = vantages.add(con, "p", "root@h", [V4, V4, V6])
    assert vantage.addresses == (V4, V6)


@pytest.mark.parametrize("name", ["", "Probe1", "probe 1", "-probe", "a" * 65,
                                  "unnamed!"])
def test_a_bad_name_is_refused(con, name):
    with pytest.raises(vantages.VantageError):
        vantages.add(con, name, "root@h", [V4])
    assert vantages.list_all(con) == []


@pytest.mark.parametrize("destination", [
    "", "-oProxyCommand=evil", "root@h x", "root@h;id", "root@h$(id)",
    "user name@host", "root@h\tx",
])
def test_a_destination_that_could_become_an_option_or_a_command_is_refused(
        con, destination):
    """The destination is one element of an argv array, placed before `--`.
    A leading dash would make it an ssh option, and anything with a space or
    a shell character is not a destination."""
    with pytest.raises(vantages.VantageError):
        vantages.add(con, "p", destination, [V4])


@pytest.mark.parametrize("destination", [
    "root@78.141.210.130", "deploy@probe2.probes.whichports.com",
    "root@[2a05:f480:1400:2015:5400:6ff:fe94:df5]", "probe2",
])
def test_an_ordinary_destination_is_accepted(con, destination):
    assert vantages.add(con, "p", destination, [V4]).destination == destination


def test_whitespace_around_a_destination_or_a_name_is_dropped(con):
    vantage = vantages.add(con, " probe1\n", " root@h\n", [V4])
    assert (vantage.name, vantage.destination) == ("probe1", "root@h")


@pytest.mark.parametrize("address", ["10.0.0.1", "127.0.0.1", "fe80::1",
                                     "100.64.0.1", "::ffff:1.2.3.4", "nope",
                                     "0.0.0.0"])
def test_an_address_that_is_not_globally_routable_is_refused(con, address):
    with pytest.raises(vantages.VantageError):
        vantages.add(con, "p", "root@h", [address])
    assert vantages.list_all(con) == []


def test_a_vantage_with_no_address_is_refused(con):
    with pytest.raises(vantages.VantageError):
        vantages.add(con, "p", "root@h", [])


def test_one_string_is_not_a_list_of_addresses(con):
    with pytest.raises(vantages.VantageError):
        vantages.add(con, "p", "root@h", V4)


def test_a_duplicate_name_is_refused(con):
    vantages.add(con, "p", "root@h", [V4])
    with pytest.raises(vantages.VantageError):
        vantages.add(con, "p", "root@other", [OTHER_V4])
    assert len(vantages.list_all(con)) == 1


def test_an_address_held_by_another_vantage_is_refused(con):
    vantages.add(con, "probe1", "root@h", [V4])
    with pytest.raises(vantages.VantageError, match="probe1"):
        vantages.add(con, "probe2", "root@other", [V4])


def test_a_refused_add_writes_nothing(con):
    vantages.add(con, "probe1", "root@h", [V4])
    with pytest.raises(vantages.VantageError):
        vantages.add(con, "probe2", "root@other", [OTHER_V4, V4])
    assert vantages.by_name(con, "probe2") is None
    assert vantages.all_addresses(con) == {V4}


# ---------------------------------------------------------------- changing


def test_off_and_on(con):
    vantages.add(con, "p", "root@h", [V4])
    vantages.set_enabled(con, "p", False)
    assert vantages.by_name(con, "p").enabled is False
    assert vantages.enabled(con) == []
    vantages.set_enabled(con, "p", True)
    assert [v.name for v in vantages.enabled(con)] == ["p"]


def test_a_disabled_vantage_keeps_its_addresses_excluded(con):
    """A box switched off in the registry is still our box."""
    vantages.add(con, "p", "root@h", [V4])
    vantages.set_enabled(con, "p", False)
    assert vantages.all_addresses(con) == {V4}


def test_set_destination(con):
    vantages.add(con, "p", "root@h", [V4])
    vantages.set_destination(con, "p", "deploy@new")
    assert vantages.by_name(con, "p").destination == "deploy@new"
    with pytest.raises(vantages.VantageError):
        vantages.set_destination(con, "p", "-bad")


def test_set_addresses_replaces_the_set(con):
    vantages.add(con, "p", "root@h", [V4, V6])
    vantages.set_addresses(con, "p", [OTHER_V4])
    assert vantages.by_name(con, "p").addresses == (OTHER_V4,)
    assert vantages.all_addresses(con) == {OTHER_V4}


def test_set_addresses_may_keep_its_own_address(con):
    vantages.add(con, "p", "root@h", [V4])
    vantages.set_addresses(con, "p", [V4, V6])
    assert vantages.by_name(con, "p").addresses == (V4, V6)


def test_set_addresses_refuses_another_vantages_address(con):
    vantages.add(con, "probe1", "root@h", [V4])
    vantages.add(con, "probe2", "root@o", [OTHER_V4])
    with pytest.raises(vantages.VantageError, match="probe1"):
        vantages.set_addresses(con, "probe2", [V4])
    assert vantages.by_name(con, "probe2").addresses == (OTHER_V4,)


def test_set_addresses_refuses_an_empty_set(con):
    vantages.add(con, "p", "root@h", [V4])
    with pytest.raises(vantages.VantageError):
        vantages.set_addresses(con, "p", [])
    assert vantages.by_name(con, "p").addresses == (V4,)


def test_remove_takes_the_addresses_with_it(con):
    vantages.add(con, "p", "root@h", [V4, V6])
    vantages.remove(con, "p")
    assert vantages.by_name(con, "p") is None
    assert vantages.all_addresses(con) == frozenset()
    assert con.execute("SELECT COUNT(*) FROM vantage_addresses").fetchone()[0] == 0


def test_changing_an_unknown_vantage_is_refused(con):
    for action in (lambda: vantages.remove(con, "p"),
                   lambda: vantages.set_enabled(con, "p", True),
                   lambda: vantages.set_destination(con, "p", "root@h"),
                   lambda: vantages.set_addresses(con, "p", [V4])):
        with pytest.raises(vantages.VantageError):
            action()


# ----------------------------------------------------------------- reading


def test_list_is_by_name_and_enabled_is_the_subset(con):
    vantages.add(con, "probe2", "root@b", [OTHER_V4])
    vantages.add(con, "probe1", "root@a", [V4, V6])
    vantages.set_enabled(con, "probe2", False)
    assert [v.name for v in vantages.list_all(con)] == ["probe1", "probe2"]
    assert [v.name for v in vantages.enabled(con)] == ["probe1"]


def test_all_addresses_spans_every_vantage(con):
    vantages.add(con, "probe1", "root@a", [V4, V6])
    vantages.add(con, "probe2", "root@b", [OTHER_V4])
    assert vantages.all_addresses(con) == {V4, V6, OTHER_V4}


# ---------------------------------------------------------------- the command


def cli_run(con, argv, capsys):
    code = vantages_cli.run(con, vantages_cli.parse_args(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_cli_list_is_honest_when_empty(con, capsys):
    code, out, _ = cli_run(con, ["list"], capsys)
    assert code == 0
    assert "no vantages" in out


def test_cli_add_list_off_on_remove(con, capsys):
    code, out, _ = cli_run(con, ["add", "--name", "probe1", "--via", "root@" + V4,
                                 "--address", V4, "--address", V6], capsys)
    assert code == 0
    assert "added probe1" in out
    code, out, _ = cli_run(con, ["list"], capsys)
    assert code == 0
    assert "probe1" in out and V4 in out and V6 in out and "root@" + V4 in out
    assert "state      on" in out
    code, out, _ = cli_run(con, ["off", "--name", "probe1"], capsys)
    assert code == 0
    assert vantages.by_name(con, "probe1").enabled is False
    code, out, _ = cli_run(con, ["on", "--name", "probe1"], capsys)
    assert vantages.by_name(con, "probe1").enabled is True
    code, out, _ = cli_run(con, ["set-via", "--name", "probe1", "--via",
                                 "deploy@x"], capsys)
    assert vantages.by_name(con, "probe1").destination == "deploy@x"
    code, out, _ = cli_run(con, ["set-addresses", "--name", "probe1",
                                 "--address", OTHER_V4], capsys)
    assert vantages.by_name(con, "probe1").addresses == (OTHER_V4,)
    code, out, _ = cli_run(con, ["remove", "--name", "probe1"], capsys)
    assert code == 0
    assert vantages.list_all(con) == []


def test_cli_refusal_is_exit_one_on_stderr(con, capsys):
    code, out, err = cli_run(con, ["add", "--name", "Bad Name", "--via",
                                   "root@h", "--address", V4], capsys)
    assert code == 1
    assert "vantage name" in err
    assert out == ""
    assert vantages.list_all(con) == []


def test_cli_add_needs_an_address(con):
    with pytest.raises(SystemExit):
        vantages_cli.parse_args(["add", "--name", "p", "--via", "root@h"])


def test_cli_never_prints_anything_but_the_rows(con, capsys):
    """Nothing in the listing is a value read from the environment or a file:
    the registry holds no credential and the listing cannot show one."""
    vantages.add(con, "p", "root@h", [V4])
    _, out, _ = cli_run(con, ["list"], capsys)
    assert "key" not in out.lower() and "password" not in out.lower()
