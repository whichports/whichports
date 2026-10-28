"""Self-hosted instances and their keys (`app/instances.py`).

What these hold: a key authenticates its own instance and its own kind and
nothing else, every other key reads as no key, only hashes are stored, and
revoking an instance ends its keys and every proof it made without touching
anybody else's.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import authz, db, instances, instances_cli, workspace

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
V4 = "185.199.108.153"
OTHER_V4 = "185.199.108.154"
THIRD_V4 = "185.199.108.155"


@pytest.fixture()
def con():
    connection = db.connect(":memory:")
    db.init(connection)
    authz.init(connection)
    instances.init(connection)
    yield connection
    connection.close()


def prove(con, address, account):
    """A published DNS proof for `address` under `account`, through the
    registry's own functions, with a resolver that answers with the token."""
    challenge = authz.start_proof(con, address, authz.METHOD_DNS_TXT,
                                  account=account, now=NOW)
    result = authz.verify_proof(con, challenge.id, now=NOW,
                                resolver=lambda name: [challenge.token])
    assert result.recorded, result.reason
    return challenge


# ------------------------------------------------------------------ schema

def test_init_is_idempotent(con):
    instances.init(con)
    instances.init(con)
    assert instances.list_all(con) == []


# ----------------------------------------------------------------- the keys

def test_add_issues_one_key_of_each_kind_with_its_own_prefix(con):
    issued = instances.add(con, "freedom", now=NOW, origin=authz.ORIGIN_INVITED)
    assert issued.api_key.startswith("whpi_")
    assert issued.proof_key.startswith("whpp_")
    assert len(issued.api_key) == len("whpi_") + 64
    assert issued.api_key != issued.proof_key
    assert issued.instance.name == "freedom"
    assert issued.instance.revoked_at is None


def test_neither_prefix_is_one_a_host_credential_or_a_proof_token_uses(con):
    """A leaked key has to say what it is, and must never be mistaken for a
    host credential or a published proof token."""
    from app import store
    for prefix in instances.PREFIXES.values():
        assert not prefix.startswith(store.CREDENTIAL_PREFIX)
        assert prefix != authz.TOKEN_PREFIX


def test_only_hashes_are_stored(con):
    """A copy of the database must hold nothing that can send a batch or
    prove an address."""
    issued = instances.add(con, "freedom", now=NOW, origin=authz.ORIGIN_INVITED)
    dump = "\n".join(con.iterdump())
    assert issued.api_key not in dump
    assert issued.proof_key not in dump
    assert instances.key_hash(issued.api_key) in dump


def test_each_key_finds_its_own_instance_and_only_as_its_own_kind(con):
    one = instances.add(con, "one", now=NOW, origin=authz.ORIGIN_INVITED)
    two = instances.add(con, "two", now=NOW, origin=authz.ORIGIN_INVITED)
    assert instances.instance_for_key(con, one.api_key, "api").name == "one"
    assert instances.instance_for_key(con, two.api_key, "api").name == "two"
    assert instances.instance_for_key(con, one.proof_key, "proof").name == "one"
    # The other kind reads as no key at all.
    assert instances.instance_for_key(con, one.api_key, "proof") is None
    assert instances.instance_for_key(con, one.proof_key, "api") is None


@pytest.mark.parametrize("key", [
    None, "", 42, b"whpi_" + b"0" * 64, "whpi_" + "0" * 64,
    "whpi_" + "a" * 500, "Bearer whpi_x", "whp_" + "0" * 64,
])
def test_anything_that_is_not_a_live_key_is_no_key(con, key):
    instances.add(con, "freedom", now=NOW, origin=authz.ORIGIN_INVITED)
    assert instances.instance_for_key(con, key, "api") is None
    assert instances.instance_for_key(con, key, "proof") is None


def test_an_unknown_kind_finds_nothing(con):
    issued = instances.add(con, "freedom", now=NOW, origin=authz.ORIGIN_INVITED)
    assert instances.instance_for_key(con, issued.api_key, "admin") is None


# --------------------------------------------------------------- the names

@pytest.mark.parametrize("name", [
    "", "Freedom", "-freedom", ".freedom", "free dom", "a" * 65, None, 7,
    "free/dom", "free\ndom",
])
def test_a_bad_name_is_refused_and_nothing_is_written(con, name):
    with pytest.raises(instances.InstanceError):
        instances.add(con, name, now=NOW, origin=authz.ORIGIN_INVITED)
    assert instances.list_all(con) == []
    assert con.execute("SELECT COUNT(*) FROM probe_instance_keys").fetchone()[0] == 0


def test_surrounding_whitespace_is_stripped_the_way_a_vantage_name_is(con):
    added = instances.add(con, " freedom\n", now=NOW, origin=authz.ORIGIN_INVITED)
    assert added.instance.name == "freedom"


def test_a_name_is_taken_once(con):
    instances.add(con, "freedom", now=NOW, origin=authz.ORIGIN_INVITED)
    with pytest.raises(instances.InstanceError, match="already exists"):
        instances.add(con, "freedom", now=NOW, origin=authz.ORIGIN_INVITED)
    assert len(instances.list_all(con)) == 1


# ------------------------------------------------------------- the account

def test_two_instances_are_two_accounts(con):
    one = instances.add(con, "one", now=NOW, origin=authz.ORIGIN_INVITED).instance
    two = instances.add(con, "two", now=NOW, origin=authz.ORIGIN_INVITED).instance
    assert one.account != two.account
    assert authz.is_instance_account(one.account)


def test_an_instance_account_is_never_a_workspace_account():
    """The gate filters on the account string, so an instance spelled like a
    workspace would read that workspace's proofs."""
    for n in range(1, 50):
        instance = authz.account_for_instance(n)
        assert instance != authz.DEFAULT_ACCOUNT
        assert instance != authz.account_for_workspace(n)
        assert not authz.is_instance_account(authz.account_for_workspace(n))
    assert not authz.is_instance_account(
        authz.account_for_workspace(workspace.DEFAULT_WORKSPACE_ID))


@pytest.mark.parametrize("value", [0, -1, True, "1", 1.0, None])
def test_an_instance_account_needs_a_real_id(value):
    with pytest.raises(ValueError):
        authz.account_for_instance(value)


@pytest.mark.parametrize("text", ["i", "i0", "i01", "w1", "default", "I1",
                                  "i1 ", "i-1", "i１", None, 1])
def test_only_what_account_for_instance_makes_is_an_instance_account(text):
    assert not authz.is_instance_account(text)


# ------------------------------------------------------------------ reissue

def test_reissue_ends_the_old_key_of_that_kind_only(con):
    issued = instances.add(con, "freedom", now=NOW, origin=authz.ORIGIN_INVITED)
    new_api = instances.reissue(con, "freedom", "api", now=NOW)
    assert instances.instance_for_key(con, issued.api_key, "api") is None
    assert instances.instance_for_key(con, new_api, "api").name == "freedom"
    # The proof key was not touched.
    assert instances.instance_for_key(con, issued.proof_key, "proof").name == "freedom"


def test_reissue_refuses_a_revoked_instance_an_unknown_one_and_a_bad_kind(con):
    instances.add(con, "freedom", now=NOW, origin=authz.ORIGIN_INVITED)
    with pytest.raises(instances.InstanceError):
        instances.reissue(con, "freedom", "admin", now=NOW)
    with pytest.raises(instances.InstanceError, match="no instance"):
        instances.reissue(con, "nobody", "api", now=NOW)
    instances.revoke(con, "freedom", now=NOW)
    with pytest.raises(instances.InstanceError, match="revoked"):
        instances.reissue(con, "freedom", "api", now=NOW)


# ------------------------------------------------------------------- revoke

def test_revoke_ends_both_keys(con):
    issued = instances.add(con, "freedom", now=NOW, origin=authz.ORIGIN_INVITED)
    revoked = instances.revoke(con, "freedom", now=NOW)
    assert revoked.revoked_at == NOW.isoformat()
    assert instances.instance_for_key(con, issued.api_key, "api") is None
    assert instances.instance_for_key(con, issued.proof_key, "proof") is None


def test_revoke_ends_every_proof_the_instance_made_and_no_one_elses(con):
    """The other instance holds an address of its own, because one address
    belongs to one instance since 2026-10-20 (docs/PRODUCT.md 5)."""
    one = instances.add(con, "one", now=NOW, origin=authz.ORIGIN_INVITED).instance
    two = instances.add(con, "two", now=NOW, origin=authz.ORIGIN_INVITED).instance
    prove(con, V4, one.account)
    prove(con, THIRD_V4, two.account)
    prove(con, V4, authz.DEFAULT_ACCOUNT)
    open_challenge = authz.start_proof(con, OTHER_V4, authz.METHOD_DNS_TXT,
                                       account=one.account, now=NOW)

    instances.revoke(con, "one", now=NOW)

    later = NOW + timedelta(minutes=1)
    assert not authz.may_probe(con, V4, now=later, account=one.account).allowed
    assert authz.may_probe(con, THIRD_V4, now=later, account=two.account).allowed
    assert authz.may_probe(con, V4, now=later).allowed
    # A challenge left open would let a verify re-prove the address a second
    # after the revoke, which is not a revoke.
    result = authz.verify_proof(con, open_challenge.id, now=later,
                                resolver=lambda name: [open_challenge.token])
    assert not result.recorded


def test_revoke_twice_is_refused_and_keeps_the_first_stamp(con):
    instances.add(con, "freedom", now=NOW, origin=authz.ORIGIN_INVITED)
    instances.revoke(con, "freedom", now=NOW)
    with pytest.raises(instances.InstanceError, match="revoked"):
        instances.revoke(con, "freedom", now=NOW + timedelta(days=1))
    assert instances.by_name(con, "freedom").revoked_at == NOW.isoformat()


def test_revoke_of_an_unknown_instance_is_refused(con):
    with pytest.raises(instances.InstanceError, match="no instance"):
        instances.revoke(con, "nobody", now=NOW)


@pytest.mark.parametrize("account", ["default", "w2", "", "i0", None])
def test_revoke_account_never_touches_anything_but_an_instance(con, account):
    """A slip in a caller must not be able to close every proof in workspace 1."""
    prove(con, V4, authz.DEFAULT_ACCOUNT)
    prove(con, OTHER_V4, authz.account_for_workspace(2))
    with pytest.raises(ValueError):
        authz.revoke_account(con, account, now=NOW)
    assert authz.may_probe(con, V4, now=NOW).allowed
    assert authz.may_probe(con, OTHER_V4, now=NOW,
                           account=authz.account_for_workspace(2)).allowed


def test_revoked_rows_are_kept_as_the_record(con):
    """Who could probe what, and when, is what an abuse report needs answered."""
    instances.add(con, "freedom", now=NOW, origin=authz.ORIGIN_INVITED)
    instances.revoke(con, "freedom", now=NOW)
    assert instances.by_name(con, "freedom") is not None
    assert len(instances.key_rows(con, instances.by_name(con, "freedom").id)) == 2


# ---------------------------------------------------------------------- CLI

def args(**fields):
    import argparse
    return argparse.Namespace(**fields)


def test_cli_add_prints_both_keys_once_and_list_prints_neither(con, capsys):
    assert instances_cli.run(con, args(command="add", name="freedom")) == 0
    printed = capsys.readouterr().out
    keys = [word for word in printed.split() if word.startswith(("whpi_", "whpp_"))]
    assert len(keys) == 2
    for key in keys:
        assert instances.instance_for_key(con, key, "api" if key.startswith(
            "whpi_") else "proof") is not None

    assert instances_cli.run(con, args(command="list")) == 0
    listed = capsys.readouterr().out
    assert "freedom" in listed
    for key in keys:
        assert key not in listed
        assert instances.key_hash(key) not in listed


def test_cli_refusals_exit_one_and_say_why(con, capsys):
    assert instances_cli.run(con, args(command="revoke", name="nobody")) == 1
    assert "no instance" in capsys.readouterr().err
    assert instances_cli.run(con, args(command="add", name="Bad Name")) == 1
    assert "instance name" in capsys.readouterr().err


def test_cli_reissue_of_a_proof_key_says_the_agents_need_it(con, capsys):
    instances_cli.run(con, args(command="add", name="freedom"))
    capsys.readouterr()
    assert instances_cli.run(con, args(command="reissue", name="freedom",
                                       kind="proof")) == 0
    assert "Re-enrol" in capsys.readouterr().out


def test_cli_revoke(con, capsys):
    instances_cli.run(con, args(command="add", name="freedom"))
    assert instances_cli.run(con, args(command="revoke", name="freedom")) == 0
    assert "revoked freedom" in capsys.readouterr().out
    assert instances.by_name(con, "freedom").revoked_at is not None


def test_cli_parses_every_command():
    assert instances_cli.parse_args(["list"]).command == "list"
    assert instances_cli.parse_args(["add", "--name", "x"]).name == "x"
    assert instances_cli.parse_args(
        ["reissue", "--name", "x", "--kind", "proof"]).kind == "proof"
    with pytest.raises(SystemExit):
        instances_cli.parse_args(["reissue", "--name", "x", "--kind", "admin"])
    assert json.dumps(vars(instances_cli.parse_args(["revoke", "--name", "x"])))


# ------------------------------------------------------------- the abuse log

def test_cli_log_says_who_asked_for_an_address_and_on_what_evidence(con, capsys):
    from app import proberapi
    proberapi.init(con)
    one = instances.add(con, "freedom", now=NOW, origin=authz.ORIGIN_INVITED).instance
    authz.record_presence_claim(con, one.account, V4, [V4], now=NOW,
                                origin=one.origin)
    proberapi.log_sent(con, one.id, "probe1", [V4], 3, NOW)
    assert instances_cli.run(con, args(command="log", address=V4)) == 0
    printed = capsys.readouterr().out
    assert "2026-09-30  freedom  from probe1  1 batches, at most 3 connects" in printed
    assert "proof  freedom  by agent, verified" in printed


def test_cli_log_of_an_address_nobody_asked_for(con, capsys):
    from app import proberapi
    proberapi.init(con)
    prove(con, OTHER_V4, authz.DEFAULT_ACCOUNT)
    assert instances_cli.run(con, args(command="log", address=OTHER_V4)) == 0
    # A workspace's own proof is not an instance's, and is not listed.
    assert "no instance asked for" in capsys.readouterr().out


def test_cli_log_refuses_what_is_not_an_address(con, capsys):
    from app import proberapi
    proberapi.init(con)
    assert instances_cli.run(con, args(command="log", address="10.0.0.1")) == 1
    assert "not a globally routable" in capsys.readouterr().err


def test_instance_for_key_is_the_new_lookups_first_value_so_there_is_one_query(con, monkeypatch):
    """The sentence that says which key is a live key is written once, in
    `instance_and_key_use`, and `instance_for_key` is its first value: a
    second copy of the door's query could drift from the first."""
    issued = instances.add(con, "one", origin=authz.ORIGIN_INVITED)
    asked = []
    real = instances.instance_and_key_use

    def counted(c, key, kind):
        asked.append((key, kind))
        return real(c, key, kind)

    monkeypatch.setattr(instances, "instance_and_key_use", counted)
    found = instances.instance_for_key(con, issued.api_key, "api")
    assert found is not None and found.name == "one"
    assert asked == [(issued.api_key, "api")]
    assert instances.instance_for_key(con, issued.proof_key, "api") is None
    assert instances.instance_for_key(con, issued.proof_key, "proof").name == "one"
    # and the query text itself appears once in the module
    source = open(instances.__file__, encoding="utf-8").read()
    assert source.count("WHERE k.key_hash = ? AND k.kind = ?") == 1


# --------------------------- how an instance was made (docs/PRODUCT.md 5)
#
# An instance that signed up proves by DNS TXT or a token file, never by
# presence, the clauses of 2026-10-20. So each instance records how it was
# made, and only an invited one proves by presence.

@pytest.mark.parametrize("origin", ["", "Invited", None, "admin", 1])
def test_an_unknown_origin_is_refused_and_nothing_is_written(con, origin):
    with pytest.raises(instances.InstanceError):
        instances.add(con, "freedom", now=NOW, origin=origin)
    assert instances.list_all(con) == []


def test_a_signup_instance_does_not_prove_by_presence(con):
    issued = instances.add(con, "stranger", now=NOW, origin=authz.ORIGIN_SIGNUP)
    found = instances.instance_for_key(con, issued.proof_key, instances.KIND_PROOF)
    assert found.origin == authz.ORIGIN_SIGNUP
    assert not found.proves_by_presence


def test_add_by_hand_is_an_invite(con, capsys):
    assert instances_cli.run(con, args(command="add", name="freedom")) == 0
    assert instances.by_name(con, "freedom").origin == authz.ORIGIN_INVITED
    assert instances.by_name(con, "freedom").proves_by_presence


def test_add_says_how_the_instance_was_made_or_is_refused(con):
    """No default: the next caller of `add`, a keys page or a signup, has to
    say it, and a stranger's instance never proves by presence by accident."""
    with pytest.raises(TypeError):
        instances.add(con, "freedom", now=NOW)
    assert instances.list_all(con) == []


def test_an_instance_from_before_the_column_was_invited(tmp_path):
    """Every instance on the box was added with `instances_cli add`, because
    no signup exists. The first init that adds the column says so of them,
    once, and of nothing written after."""
    path = str(tmp_path / "old.db")
    old = db.connect(path)
    old.execute("CREATE TABLE probe_instances (id INTEGER PRIMARY KEY,"
                " name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,"
                " revoked_at TEXT)")
    old.execute("INSERT INTO probe_instances (name, created_at) VALUES"
                " ('freedom', ?)", (NOW.isoformat(),))
    old.commit()
    instances.init(old)
    assert instances.by_name(old, "freedom").proves_by_presence
    # A row written later with no origin, which add never writes, is not.
    old.execute("INSERT INTO probe_instances (name, created_at) VALUES"
                " ('blank', ?)", (NOW.isoformat(),))
    old.commit()
    instances.init(old)
    assert not instances.by_name(old, "blank").proves_by_presence
    assert instances.by_name(old, "freedom").proves_by_presence
    old.close()


def test_cli_list_says_how_each_instance_was_made(con, capsys):
    instances.add(con, "freedom", now=NOW, origin=authz.ORIGIN_INVITED)
    instances.add(con, "stranger", now=NOW, origin=authz.ORIGIN_SIGNUP)
    assert instances_cli.run(con, args(command="list")) == 0
    listed = capsys.readouterr().out
    assert "    made       invited" in listed
    assert "    made       signup" in listed


def test_cli_log_says_when_an_address_is_excluded(con, capsys):
    from app import proberapi
    proberapi.init(con)
    authz.exclude(con, V4, now=NOW)
    assert instances_cli.run(con, args(command="log", address=V4)) == 0
    printed = capsys.readouterr().out
    assert f"excluded since {NOW.isoformat()}" in printed
