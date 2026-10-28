"""Which account an authorisation is written for, and which row a re-proof
refreshes.

`app/authz.py` has filtered the gate on the account since workspaces landed,
and `_record` is the write half of the same question. It was passing no
account at all, so every write asked about workspace 1 whatever workspace it
was writing for. Two failures came out of that and both are pinned here:

  - **a proof in one workspace refreshed another workspace's row.** The
    workspace that did the proving got no authorisation and was told it had
    one, and the workspace that did nothing had its expiry pushed out on
    somebody else's evidence. That is the cross-workspace reach SI-6 forbids,
    reached through the write path rather than the read path.
  - **an agent outside workspace 1 never found its own live row**, so every
    report inserted another one. At a report every fifteen minutes that is
    ninety-six rows a day per host, which buries the history the row is kept
    for.

These are behaviours of the module, so they are checked against the module
rather than through a route.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import authz, db, store

# Two addresses that are globally routable unicast, which is all the registry
# will hold. github.com's pages range, the same one the neighbouring authz
# tests use.
ADDRESS = "185.199.108.153"

NOON = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


@pytest.fixture()
def con(tmp_path):
    c = db.connect(str(tmp_path / "a.db"))
    db.init(c)
    authz.init(c)
    yield c
    c.close()


@pytest.fixture()
def second(con):
    """A second workspace, and the account string its authorisations carry."""
    workspace_id = db.create_workspace(con, "second")
    return workspace_id, authz.account_for_workspace(workspace_id)


def prove_published(con, account, address=ADDRESS, now=None, host_id=None):
    """One HTTP token proof, verified with the token it minted."""
    challenge = authz.start_proof(con, address, authz.METHOD_HTTP_TOKEN,
                                  account=account, now=now, host_id=host_id)
    result = authz.verify_proof(con, challenge.id, now=now,
                                fetcher=lambda url: challenge.token + "\n")
    return result


def document_claiming(address, family="v4"):
    """The half of the agent-derived proof the host asserts: it says it holds
    the address on an interface."""
    return json.dumps({"interface_addresses":
                       {"addresses": [{"address": address, "family": family}]}})


# ------------------------------------------------- a proof stays in its own workspace

def test_a_proof_in_one_workspace_does_not_refresh_another_workspaces_row(con, second):
    """The measured failure. Workspace 1 proves the address, then workspace 2
    proves the same address by the same method with no host attached. The two
    rows have to be two rows."""
    _workspace_id, other = second
    first = prove_published(con, authz.DEFAULT_ACCOUNT, now=NOON)
    assert first.recorded

    later = NOON + timedelta(hours=1)
    theirs = prove_published(con, other, now=later)
    assert theirs.recorded
    assert theirs.authorization_id != first.authorization_id

    rows = con.execute("SELECT id, account, verified_at FROM authorizations"
                       " ORDER BY id").fetchall()
    assert [row["account"] for row in rows] == [authz.DEFAULT_ACCOUNT, other]
    # The first workspace's row is untouched: its evidence and its expiry are
    # still the ones its own proof wrote an hour ago.
    assert rows[0]["verified_at"] == NOON.isoformat()


def test_each_workspace_gets_the_answer_it_proved(con, second):
    """The other half of the same fact, asked through the gate. Neither
    workspace's proof may answer for the other, in either direction."""
    _workspace_id, other = second
    assert not authz.may_probe(con, ADDRESS, account=other).allowed

    prove_published(con, other, now=NOON)
    assert authz.may_probe(con, ADDRESS, now=NOON, account=other).allowed
    # And workspace 1, which proved nothing, still may not probe it.
    assert not authz.may_probe(con, ADDRESS, now=NOON,
                               account=authz.DEFAULT_ACCOUNT).allowed


def test_one_workspace_revoking_does_not_take_the_others_proof_away(con, second):
    """Both workspaces prove the address, one revokes. Only that one loses it.

    `revoke` already scoped itself by account; this is here because the two
    rows have to exist before the scoping can mean anything, and before the
    fix there was only ever one row to revoke.
    """
    _workspace_id, other = second
    prove_published(con, authz.DEFAULT_ACCOUNT, now=NOON)
    prove_published(con, other, now=NOON)

    authz.revoke(con, ADDRESS, now=NOON, account=other)
    assert not authz.may_probe(con, ADDRESS, now=NOON, account=other).allowed
    assert authz.may_probe(con, ADDRESS, now=NOON,
                           account=authz.DEFAULT_ACCOUNT).allowed


# ------------------------------------------------------ re-proof refreshes one row

def test_an_agent_outside_workspace_one_refreshes_its_row_rather_than_adding_one(con):
    """Four reports a quarter of an hour apart, which is what a running agent
    does in an hour. One row, its stamp moved forward each time."""
    workspace_id = db.create_workspace(con, "second")
    host_id, _credential = store.add_host(con, "boxie", workspace_id=workspace_id)
    document = document_claiming(ADDRESS)

    identifiers = []
    for tick in range(4):
        result = authz.record_agent_proof(con, host_id, ADDRESS, document,
                                          now=NOON + timedelta(minutes=15 * tick))
        assert result.recorded, result.reason
        identifiers.append(result.authorization_id)

    assert len(set(identifiers)) == 1
    rows = con.execute("SELECT account, verified_at FROM authorizations").fetchall()
    assert len(rows) == 1
    assert rows[0]["account"] == authz.account_for_workspace(workspace_id)
    assert rows[0]["verified_at"] == (NOON + timedelta(minutes=45)).isoformat()


def test_an_agent_in_workspace_one_still_refreshes_its_row(con):
    """The behaviour that was already right, kept honest. Workspace 1 was the
    one case the missing argument happened to get correct, so a fix that broke
    it would be invisible without this."""
    host_id, _credential = store.add_host(con, "boxie")
    document = document_claiming(ADDRESS)
    first = authz.record_agent_proof(con, host_id, ADDRESS, document, now=NOON)
    again = authz.record_agent_proof(con, host_id, ADDRESS, document,
                                     now=NOON + timedelta(minutes=15))
    assert first.authorization_id == again.authorization_id
    assert con.execute("SELECT COUNT(*) AS n FROM authorizations"
                       ).fetchone()["n"] == 1


def test_two_workspaces_agents_on_one_address_keep_one_row_each(con):
    """A shared outward address, which is what two hosts behind one NAT look
    like from here. Each host still corroborates it, so each workspace holds
    its own row and neither grows a second one."""
    other_workspace = db.create_workspace(con, "second")
    mine, _c1 = store.add_host(con, "mine")
    theirs, _c2 = store.add_host(con, "theirs", workspace_id=other_workspace)
    document = document_claiming(ADDRESS)

    for tick in range(3):
        when = NOON + timedelta(minutes=15 * tick)
        assert authz.record_agent_proof(con, mine, ADDRESS, document,
                                        now=when).recorded
        assert authz.record_agent_proof(con, theirs, ADDRESS, document,
                                        now=when).recorded

    accounts = [row["account"] for row in
                con.execute("SELECT account FROM authorizations ORDER BY id")]
    assert accounts == [authz.DEFAULT_ACCOUNT,
                        authz.account_for_workspace(other_workspace)]


def test_a_lapsed_row_still_gets_a_new_one_rather_than_being_revived(con):
    """The rule the account argument must not change: a proof that lapsed
    leaves its row as the record of what went away, and the new proof is a new
    row."""
    workspace_id = db.create_workspace(con, "second")
    host_id, _credential = store.add_host(con, "boxie", workspace_id=workspace_id)
    document = document_claiming(ADDRESS)

    first = authz.record_agent_proof(con, host_id, ADDRESS, document, now=NOON)
    after_expiry = NOON + timedelta(seconds=authz.AGENT_TTL_SECONDS + 1)
    second_proof = authz.record_agent_proof(con, host_id, ADDRESS, document,
                                            now=after_expiry)
    assert second_proof.authorization_id != first.authorization_id
    assert con.execute("SELECT COUNT(*) AS n FROM authorizations"
                       ).fetchone()["n"] == 2
