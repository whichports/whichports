"""A server has one token for its token file (docs/RECORD.md 4.329).

One machine serves one file at the well-known path and the file holds one
token. Until 2026-10-03 every address was given a token of its own, so a
second address of the same machine could only be proved by overwriting the
token the first is read against, and the first then failed its next reading
(4.297, measured on a real server).

What is reviewed here is narrow on purpose. Where a token comes from changed:
a token file proof started for a server that holds a live one is given that
proof's token. What proves an address did not change at all: each address is
fetched at its own URL and compared with its own challenge's hash.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import authz, db, store

T0 = datetime(2026, 10, 3, 15, 32, 2, tzinfo=timezone.utc)
MINUTE = timedelta(minutes=1)
DAY = timedelta(days=1)

V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"
OTHER_V4 = "185.199.109.153"

HTTP = authz.METHOD_HTTP_TOKEN
DNS = authz.METHOD_DNS_TXT


@pytest.fixture()
def con(tmp_path):
    c = db.connect(str(tmp_path / "one-token.db"))
    db.init(c)
    authz.init(c)
    yield c
    c.close()


def url_of(address):
    """Written out here, not asked of the registry, so the test holds the
    address a file is read from independently of the code that builds it."""
    host = f"[{address}]" if ":" in address else address
    return f"http://{host}:80/.well-known/whichports-authorization"


class Web:
    """What each address serves at the well-known path, and every fetch the
    registry made, in order."""

    def __init__(self):
        self.files = {}
        self.fetched = []

    def serve(self, body, *addresses):
        for address in addresses:
            self.files[url_of(address)] = body

    def fetch(self, url, timeout=0):
        self.fetched.append(url)
        if url not in self.files:
            raise authz.ProofError("could not read the token file: URLError")
        return self.files[url]


@pytest.fixture()
def web():
    return Web()


def start(con, host_id, address, now=T0, method=HTTP, account=authz.DEFAULT_ACCOUNT):
    return authz.start_proof(con, address, method, account=account, now=now,
                             host_id=host_id)


def verify(con, challenge, web, now=T0):
    return authz.verify_proof(con, challenge.id, now=now, fetcher=web.fetch)


def prove(con, host_id, address, web, now=T0, account=authz.DEFAULT_ACCOUNT):
    """Start, publish on that one address, verify. The token it was given."""
    challenge = start(con, host_id, address, now=now, account=account)
    web.serve(challenge.token, address)
    result = verify(con, challenge, web, now=now)
    assert result.recorded, result.reason
    return challenge


def live_row(con, address):
    return con.execute(
        "SELECT * FROM authorizations WHERE target = ? AND revoked_at IS NULL"
        " AND expired_at IS NULL", (address,)).fetchone()


def second_workspace(con):
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'other', 't')")
    con.commit()
    return authz.account_for_workspace(2)


# ------------------------------------------------- the same token, each address
# still proved by its own fetch

def test_a_second_address_of_a_server_is_given_the_servers_token(con, web):
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)

    second = start(con, server, V6, now=T0 + 11 * MINUTE)

    assert second.token == first.token
    assert second.id != first.id
    assert second.publish_at == url_of(V6)
    assert (second.target, second.family) == (V6, "v6")


def test_the_second_challenge_stores_a_hash_and_never_the_token(con, web):
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    second = start(con, server, V6)

    rows = con.execute("SELECT * FROM authz_challenges ORDER BY id").fetchall()
    assert [row["token_hash"] for row in rows] == [authz.token_hash(first.token)] * 2
    for row in rows:
        assert second.token not in [str(row[key]) for key in row.keys()]


def test_the_second_address_is_not_proved_until_its_own_fetch_returns_the_token(con, web):
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    second = start(con, server, V6, now=T0 + 11 * MINUTE)

    # Started, and the first address already serves this very token. That
    # proves nothing about the second address.
    assert not authz.may_probe(con, V6, now=T0 + 11 * MINUTE).allowed
    assert [r["target"] for r in authz.live_addresses_for_host(con, server, now=T0)] == [V4]

    web.fetched.clear()
    web.serve(first.token, V6)
    result = verify(con, second, web, now=T0 + 11 * MINUTE)

    assert result.recorded and result.code == "proved"
    assert web.fetched == [url_of(V6)], "the address being proved is the one fetched"
    assert authz.may_probe(con, V6, now=T0 + 11 * MINUTE).allowed
    # Its own row, with its own thirty days.
    row = live_row(con, V6)
    assert row["host_id"] == server and row["method"] == HTTP
    assert row["expires_at"] == (T0 + 11 * MINUTE + 30 * DAY).isoformat()
    assert live_row(con, V4)["expires_at"] == (T0 + 30 * DAY).isoformat()
    assert json.loads(row["evidence"]) == {"read": first.token, "read_from": url_of(V6)}


@pytest.mark.parametrize("served, code", [
    (None, "evidence_unreadable"),            # nothing answers on that address
    ("something else\n", "token_not_found"),  # a file, and not the token
])
def test_a_second_address_that_does_not_serve_the_token_is_a_no(con, web, served, code):
    server = store.add_address_host(con, "web-01")
    prove(con, server, V4, web)
    before = dict(live_row(con, V4))
    second = start(con, server, V6, now=T0 + 11 * MINUTE)
    if served is not None:
        web.serve(served, V6)

    result = verify(con, second, web, now=T0 + 11 * MINUTE)

    assert not result.recorded and result.code == code
    assert not authz.may_probe(con, V6, now=T0 + 11 * MINUTE).allowed
    assert live_row(con, V6) is None
    # The first address is exactly as it was.
    assert dict(live_row(con, V4)) == before
    assert authz.may_probe(con, V4, now=T0 + 11 * MINUTE).allowed


def test_both_addresses_renew_on_the_one_token(con, web):
    """The case 4.297 measured, with its own clock: v4 proved at 15:32, v6
    added at 15:43, and the readings of the last seven days. With a token for
    each address the first one failed here. With one token both pass."""
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web, now=T0)
    second = start(con, server, V6, now=T0 + 11 * MINUTE)
    web.serve(second.token, V6)
    assert verify(con, second, web, now=T0 + 11 * MINUTE).recorded
    assert web.files[url_of(V4)] == web.files[url_of(V6)] == first.token

    web.fetched.clear()
    day_24 = T0 + 24 * DAY
    out = authz.renew_published(con, now=day_24, fetcher=web.fetch)

    assert sorted(out["renewed"]) == sorted([V4, V6])
    assert out["failed"] == [] and out["skipped"] == []
    assert sorted(web.fetched) == sorted([url_of(V4), url_of(V6)]), \
        "each address is fetched once, at its own address"
    for address in (V4, V6):
        row = live_row(con, address)
        assert row["expires_at"] == (day_24 + 30 * DAY).isoformat()
        assert row["renewal_failure"] is None


def test_renewal_still_reads_each_address_by_itself(con, web):
    """One token does not make one proof. An address that stops serving the
    file fails its own reading while the other one renews."""
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    second = start(con, server, V6)
    web.serve(second.token, V6)
    assert verify(con, second, web).recorded

    del web.files[url_of(V6)]
    day_24 = T0 + 24 * DAY
    out = authz.renew_published(con, now=day_24, fetcher=web.fetch)

    assert out["renewed"] == [V4]
    assert [target for target, _reason in out["failed"]] == [V6]
    assert live_row(con, V4)["expires_at"] == (day_24 + 30 * DAY).isoformat()
    # Since 2026-10-20 a proof whose evidence is gone ends at its reading
    # (docs/PRODUCT.md 5), where it used to run to its own expiry.
    assert out["ended"] == [V6] and live_row(con, V6) is None
    assert first.token == second.token


# ------------------------------------------------------ never another server's

@pytest.mark.parametrize("other_workspace", [False, True])
def test_another_server_gets_another_token_and_the_first_ones_proves_nothing_for_it(
        con, web, other_workspace):
    account, workspace_id = authz.DEFAULT_ACCOUNT, 1
    if other_workspace:
        account, workspace_id = second_workspace(con), 2
    first_server = store.add_address_host(con, "web-01")
    other_server = store.add_address_host(con, "web-02", workspace_id=workspace_id)
    first = prove(con, first_server, V4, web)

    other = start(con, other_server, OTHER_V4, account=account)
    assert other.token != first.token

    # The other server's address serves the first server's token.
    web.serve(first.token, OTHER_V4)
    result = verify(con, other, web)
    assert not result.recorded and result.code == "token_not_found"
    assert not authz.may_probe(con, OTHER_V4, now=T0, account=account).allowed

    # And the same address as the first server's, asked for by the other one,
    # is no different: the file there holds the first server's token.
    same_address = start(con, other_server, V4, account=account)
    assert same_address.token not in (first.token, other.token)
    result = verify(con, same_address, web)
    assert not result.recorded and result.code == "token_not_found"


def test_a_server_is_never_given_a_token_through_another_account(con, web):
    """The account is part of the question, as everywhere in the registry. A
    caller that names the right server and the wrong account gets a new
    token, never the server's."""
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    other_account = second_workspace(con)

    asked = start(con, server, V6, account=other_account)

    assert asked.token != first.token


# ---------------------------------------- what lends a token and what does not

def test_a_token_is_shown_again_only_for_a_live_proof_of_the_same_server(con, web):
    server = store.add_address_host(con, "web-01")
    other_server = store.add_address_host(con, "web-02")

    # A pending challenge lends nothing: its token is a hash here.
    pending = start(con, server, V4)
    assert start(con, server, V6).token != pending.token

    # Verified, it does, to its own server and to no other.
    web.serve(pending.token, V4)
    assert verify(con, pending, web).recorded
    assert start(con, server, V6).token == pending.token
    assert start(con, other_server, OTHER_V4).token != pending.token

    # Revoked, it lends nothing again.
    authz.revoke(con, V4, now=T0 + MINUTE)
    assert start(con, server, V6, now=T0 + 2 * MINUTE).token != pending.token


def test_two_addresses_started_before_either_is_verified_get_two_tokens(con, web):
    """The first token cannot be shown a second time, so the second address
    has its own. One file holds one of them. The address whose token is not
    in the file is told so at once, and starting it again gives the server's
    token, which the file already holds."""
    server = store.add_address_host(con, "web-01")
    for_v4 = start(con, server, V4)
    for_v6 = start(con, server, V6)
    assert for_v4.token != for_v6.token

    web.serve(for_v6.token, V4, V6)     # one machine, one file, the later token
    assert verify(con, for_v6, web).recorded
    refused = verify(con, for_v4, web)
    assert not refused.recorded and refused.code == "token_not_found"
    assert refused.reason == f"the token was not found at {url_of(V4)}"

    again = start(con, server, V4, now=T0 + MINUTE)
    assert again.token == for_v6.token
    assert verify(con, again, web, now=T0 + MINUTE).recorded
    assert authz.may_probe(con, V4, now=T0 + MINUTE).allowed


def test_an_old_pair_with_two_tokens_is_mended_by_starting_the_address_again(con, web):
    """Rows as the registry wrote them before this change: each address
    proved with its own token, the file since overwritten with the second.
    Nothing about how they are read moved, so the first address fails its
    next reading exactly as 4.297 measured, in the words it had. What is new
    is the way out: starting that address again answers the token the file
    already holds."""
    server = store.add_address_host(con, "web-01")
    for_v4 = start(con, server, V4, now=T0)
    for_v6 = start(con, server, V6, now=T0)
    web.serve(for_v4.token, V4)
    assert verify(con, for_v4, web, now=T0).recorded
    web.serve(for_v6.token, V4, V6)     # proving v6 overwrote the one file
    assert verify(con, for_v6, web, now=T0 + 11 * MINUTE).recorded

    day_24 = T0 + 24 * DAY
    out = authz.renew_published(con, now=day_24, fetcher=web.fetch)
    assert out["renewed"] == [V6]
    assert out["failed"] == [(V4, f"the token was not found at {url_of(V4)}")]
    # It ends at that reading since 2026-10-20 (docs/PRODUCT.md 5).
    assert out["ended"] == [V4] and live_row(con, V4) is None

    again = start(con, server, V4, now=day_24)
    assert again.token == for_v6.token
    assert verify(con, again, web, now=day_24).recorded
    assert live_row(con, V4)["expires_at"] == (day_24 + 30 * DAY).isoformat()
    # And from here on the first address is read against the token in the file.
    later = authz.renew_published(con, now=day_24 + 24 * DAY, fetcher=web.fetch)
    assert sorted(later["renewed"]) == sorted([V4, V6]) and later["failed"] == []


def test_an_existing_proof_keeps_being_read_against_its_own_token(con, web):
    """A server with one address, proved before the change, is untouched by
    it: the same challenge, the same hash, renewed for as long as the file
    is there."""
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    now = T0
    for _ in range(3):
        now = now + 24 * DAY
        out = authz.renew_published(con, now=now, fetcher=web.fetch)
        assert out["renewed"] == [V4] and out["failed"] == []
    challenges = con.execute("SELECT id, token_hash FROM authz_challenges").fetchall()
    assert [(row["id"], row["token_hash"]) for row in challenges] == [
        (first.id, authz.token_hash(first.token))]


def test_a_revoked_proofs_token_is_gone_with_it(con, web):
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    authz.revoke(con, V4, now=T0 + MINUTE)

    again = start(con, server, V4, now=T0 + 2 * MINUTE)
    assert again.token != first.token
    # The old file is still being served. It proves nothing any more.
    result = verify(con, again, web, now=T0 + 2 * MINUTE)
    assert not result.recorded and result.code == "token_not_found"
    assert start(con, server, V6, now=T0 + 2 * MINUTE).token != first.token


def test_a_proof_marked_revoked_lends_nothing_whatever_its_challenge_says(con, web):
    """`revoke` cancels the challenge as well, which alone would stop the
    lending. The mark on the proof has to stop it by itself too, so that no
    later way of revoking can leave a token on offer."""
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    con.execute("UPDATE authorizations SET revoked_at = ?", (T0.isoformat(),))
    con.commit()

    assert start(con, server, V6).token != first.token


@pytest.mark.parametrize("swept", [False, True])
def test_a_lapsed_proof_lends_nothing(con, web, swept):
    """Decided against the clock, so a sweep that never ran changes nothing,
    and decided by the written-off mark as well once it has."""
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    later = T0 + 30 * DAY + MINUTE
    if swept:
        authz.sweep(con, now=later)

    assert start(con, server, V6, now=later).token != first.token


def test_a_lapsed_proof_does_not_lend_once_the_clock_steps_back(con, web):
    """The same posture as the gate: a row the sweep wrote off stays dead
    when a clock correction puts the present before its expiry again."""
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    authz.sweep(con, now=T0 + 31 * DAY)

    assert start(con, server, V6, now=T0 + DAY).token != first.token


def test_a_removed_servers_token_is_not_lent(con, web):
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    assert store.revoke_host(con, "web-01")

    assert start(con, server, V6).token != first.token


def test_a_deleted_servers_token_never_reaches_the_server_made_after_it(con, web):
    """A deleted server's rows go with it. The next server made can be given
    the same row number, and it must start from nothing."""
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    assert store.revoke_host(con, "web-01")
    assert store.delete_host(con, "web-01")

    newcomer = store.add_address_host(con, "web-02")
    assert start(con, newcomer, V4).token != first.token


def test_a_proof_whose_challenge_was_cancelled_lends_nothing(con, web):
    """A token is lent only while the registry still expects it. Renewal
    would refuse this proof for the same reason, so a second address must
    not be built on it."""
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    con.execute("UPDATE authz_challenges SET cancelled_at = ? WHERE id = ?",
                (T0.isoformat(), first.id))
    con.commit()

    assert start(con, server, V6).token != first.token


UNREADABLE = [
    "not json",
    "[]",
    "{}",
    '{"read": 5}',
    '{"read": null}',
    '{"read": "hello"}',
    '{"read": "whpa_"}',
    json.dumps({"read": "whpa_" + "z" * 64}),
    json.dumps({"read": "whpa_" + "A" * 64}),
    json.dumps({"read": "whpa_" + "a" * 63}),
    json.dumps({"read": "whp_" + "a" * 64}),
]


@pytest.mark.parametrize("evidence", UNREADABLE)
def test_evidence_that_cannot_be_read_lends_nothing(con, web, evidence):
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    con.execute("UPDATE authorizations SET evidence = ?", (evidence,))
    con.commit()

    second = start(con, server, V6)

    assert second.token != first.token
    assert second.token.startswith(authz.TOKEN_PREFIX) and len(second.token) == 69


@pytest.mark.parametrize("padding", [" ", "\n", "\t"])
@pytest.mark.parametrize("side", ["before", "after"])
def test_evidence_holding_the_token_and_something_beside_it_lends_nothing(
        con, web, padding, side):
    """The string handed out is hashed onto the new challenge as it stands.
    A token with a space beside it would be a challenge no file can meet."""
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)
    padded = padding + first.token if side == "before" else first.token + padding
    con.execute("UPDATE authorizations SET evidence = ?",
                (json.dumps({"read": padded, "read_from": url_of(V4)}),))
    con.commit()

    second = start(con, server, V6)

    assert second.token != padded and second.token != first.token


def test_evidence_naming_a_token_the_registry_does_not_expect_lends_nothing(con, web):
    """The evidence row is text. A well-formed token in it that is not the
    one this proof's own challenge holds is never shown to anyone."""
    server = store.add_address_host(con, "web-01")
    prove(con, server, V4, web)
    planted = authz.new_token()
    con.execute("UPDATE authorizations SET evidence = ?",
                (json.dumps({"read": planted, "read_from": url_of(V4)}),))
    con.commit()

    assert start(con, server, V6).token != planted


def test_with_several_live_proofs_the_newest_reading_is_the_servers_token(con, web):
    """Only an old pair can hold two. The file is known to have held the
    token that was read last, so that is the one a new address is given."""
    server = store.add_address_host(con, "web-01")
    for_v4 = start(con, server, V4, now=T0)
    for_v6 = start(con, server, V6, now=T0)
    web.serve(for_v4.token, V4)
    assert verify(con, for_v4, web, now=T0).recorded
    web.serve(for_v6.token, V4, V6)
    assert verify(con, for_v6, web, now=T0 + 11 * MINUTE).recorded

    assert start(con, server, OTHER_V4, now=T0 + 12 * MINUTE).token == for_v6.token


# ------------------------------------------------------------ DNS TXT untouched

def test_dns_txt_still_gives_every_address_its_own_token(con):
    server = store.add_address_host(con, "web-01")
    first = start(con, server, V4, method=DNS)
    result = authz.verify_proof(con, first.id, now=T0,
                                resolver=lambda name: [first.token])
    assert result.recorded

    second = start(con, server, V6, method=DNS)

    assert second.token != first.token


def test_a_txt_record_holding_the_servers_file_token_proves_nothing(con, web):
    server = store.add_address_host(con, "web-01")
    file_proof = prove(con, server, V4, web)

    by_dns = start(con, server, V6, method=DNS)
    assert by_dns.token != file_proof.token
    result = authz.verify_proof(con, by_dns.id, now=T0,
                                resolver=lambda name: [file_proof.token])

    assert not result.recorded and result.code == "token_not_found"
    assert not authz.may_probe(con, V6, now=T0).allowed


def test_a_dns_proof_never_lends_its_token_to_a_token_file(con):
    server = store.add_address_host(con, "web-01")
    by_dns = start(con, server, V4, method=DNS)
    assert authz.verify_proof(con, by_dns.id, now=T0,
                              resolver=lambda name: [by_dns.token]).recorded

    assert start(con, server, V6, method=HTTP).token != by_dns.token


# ------------------------------------------------------- a proof with no server

@pytest.mark.parametrize("account", [authz.DEFAULT_ACCOUNT, authz.account_for_instance(3)])
def test_a_proof_for_the_account_alone_keeps_a_token_for_each_address(con, web, account):
    """The prober API and the command line start a proof with no server. The
    registry does not know which of an account's addresses are one machine,
    so nothing is shared there. Unchanged, and held here so that it stays a
    decision and never becomes an accident."""
    first = prove(con, None, V4, web, account=account)

    second = start(con, None, V6, account=account)

    assert second.token != first.token


def test_a_servers_token_is_not_lent_to_a_proof_with_no_server(con, web):
    server = store.add_address_host(con, "web-01")
    first = prove(con, server, V4, web)

    assert start(con, None, V6).token != first.token
