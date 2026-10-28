"""A shared address, and the four rules that close it (docs/PRODUCT.md 5,
the clauses of 2026-10-20).

A self-hosted instance's presence proves the address its request arrived
from when the request also names it. A request made by hand with a proof key,
sent from a carrier or office NAT, a VPN or a Tor exit, does both, so it
proved an address shared with strangers. It then lasted a week, a revoke was
undone by the next presence, and a second instance could prove the same
address. What these hold, at the registry:

  - a proof by presence lasts an hour, and an agent renewing it keeps it
  - one address belongs to one instance, also when two race for it
  - an instance that signed up never proves by presence
  - an address on the exclusion list is never proved and never probed, by
    any account, new ones too, and taking it off restores nothing
  - the proofs stored before this are shortened once, and never widened

Edge cases first, the everyday case last in each part.
"""
import json
import pathlib
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from app import authz, db, store

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)
SECOND = timedelta(seconds=1)
MINUTE = timedelta(minutes=1)
DAY = timedelta(days=1)

V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"
OTHER_V4 = "185.199.108.154"
ADDRESSES = [f"185.199.108.{n}" for n in range(155, 160)]

ONE = authz.account_for_instance(1)
TWO = authz.account_for_instance(2)
# Spelled out rather than read off the module, so the words a database
# stores are held here independently of the code that writes them.
INVITED = "invited"
SIGNUP = "signup"
DNS = authz.METHOD_DNS_TXT

REPO = pathlib.Path(__file__).resolve().parents[2]


@pytest.fixture()
def path(tmp_path):
    return str(tmp_path / "cp.db")


@pytest.fixture()
def con(path):
    connection = db.connect(path)
    db.init(connection)
    authz.init(connection)
    yield connection
    connection.close()


def claim(con, account, address=V4, moment=NOW, origin=INVITED):
    return authz.record_presence_claim(con, account, address, [address],
                                       now=moment, origin=origin)


def allowed(con, account, moment, address=V4):
    return authz.may_probe(con, address, now=moment, account=account).allowed


def live_rows(con, account, moment=NOW):
    return [(row["id"], row["target"], row["expires_at"], row["evidence"])
            for row in authz.live_for_account(con, account, now=moment)]


def dns_proof(con, account, address=V4, moment=NOW, also=()):
    """A DNS TXT proof. `also` is other tokens the reverse zone still holds,
    which is how an earlier holder's proof stays standing."""
    challenge = authz.start_proof(con, address, DNS, account=account, now=moment)
    return challenge, authz.verify_proof(
        con, challenge.id, now=moment,
        resolver=lambda name: [challenge.token, *also])


# ================================================= a proof lasts an hour

def test_a_presence_proof_is_refused_an_hour_and_a_second_after_it_was_made(con):
    assert claim(con, ONE).recorded
    assert not allowed(con, ONE, NOW + HOUR + SECOND)
    # The gate counts the end itself as lapsed, the way it always has.
    assert not allowed(con, ONE, NOW + HOUR)
    assert allowed(con, ONE, NOW + HOUR - SECOND)


def test_the_hour_is_the_constant_and_the_week_is_kept_for_our_own_agents():
    assert authz.HOUR_TTL_SECONDS == 60 * 60
    assert authz.AGENT_TTL_SECONDS == 7 * 24 * 60 * 60


def test_a_renewal_at_59_minutes_carries_the_same_row_another_hour(con):
    first = claim(con, ONE)
    again = claim(con, ONE, moment=NOW + 59 * MINUTE)
    assert again.recorded and again.authorization_id == first.authorization_id
    assert allowed(con, ONE, NOW + HOUR + 58 * MINUTE)
    assert not allowed(con, ONE, NOW + HOUR + 59 * MINUTE + SECOND)
    assert len(authz.list_authorizations(con)) == 1


def test_a_proof_renewed_too_late_is_a_new_row_after_the_lapsed_one(con):
    """An agent off for more than an hour: its address is not probed in the
    gap, and its next presence proves it again, the lapsed row kept as the
    history."""
    first = claim(con, ONE)
    assert not allowed(con, ONE, NOW + HOUR + MINUTE)
    again = claim(con, ONE, moment=NOW + HOUR + MINUTE)
    assert again.recorded and again.authorization_id != first.authorization_id
    assert allowed(con, ONE, NOW + HOUR + 2 * MINUTE)


def test_the_agents_timer_renews_well_inside_the_hour():
    """The hour rests on the agent's own timer: a run every quarter hour with
    up to two minutes of delay, and every run sends its presence. Two runs in
    a row may fail and the proof still holds, because the third comes at most
    47 minutes after the last one that went through."""
    timer = (REPO / "agent" / "packaging" / "systemd"
             / "whichports-agent.timer").read_text(encoding="utf-8")
    every = int(re.search(r"^OnCalendar=\*:0/(\d+)$", timer, re.M).group(1))
    delay = re.search(r"^RandomizedDelaySec=(\d+)m$", timer, re.M)
    longest_gap_after_two_misses = (3 * every + int(delay.group(1))) * 60
    assert longest_gap_after_two_misses < authz.HOUR_TTL_SECONDS


def test_the_agent_sends_presence_on_every_run_before_its_report():
    """Read in the agent's own source: `deliver` proves to the prober API
    first, on every run of timer and oneshot mode, whatever the instance's
    own control plane answers afterwards."""
    main = (REPO / "agent" / "cmd" / "agent" / "main.go").read_text(encoding="utf-8")
    deliver = main.split("func deliver(")[1].split("\n}\n")[0]
    assert deliver.index("client.ProveToProber(") < deliver.index("client.Send(")
    assert main.count("return deliver(report.NewClient(cfg), document)") == 2


# ============================================ one address, one instance

def test_a_second_instance_is_refused_an_address_the_first_holds(con):
    claim(con, ONE)
    before = live_rows(con, ONE)
    result = claim(con, TWO, moment=NOW + MINUTE)
    assert not result.recorded and result.code == "address_held"
    assert not allowed(con, TWO, NOW + MINUTE)
    # What the first instance holds did not move, not even its expiry.
    assert live_rows(con, ONE) == before
    assert allowed(con, ONE, NOW + MINUTE)


def test_the_refusal_is_a_class_and_the_sentence_names_no_instance(con):
    claim(con, ONE)
    result = claim(con, TWO)
    assert result.code in authz.PROOF_CODES
    assert ONE not in result.reason and TWO not in result.reason


def test_a_second_instance_is_refused_at_verify_and_its_challenge_stays_open(con):
    """Starting a proof answers nothing about who holds an address. Verify
    does, once the evidence was read: the one asking controls the address.
    Held here by a published proof, which a published proof does not
    outrank."""
    first, held = dns_proof(con, ONE)
    assert held.recorded
    challenge, result = dns_proof(con, TWO, moment=NOW + MINUTE, also=[first.token])
    assert challenge.token  # the start was not refused
    assert not result.recorded and result.code == "address_held"
    assert not allowed(con, TWO, NOW + MINUTE)
    assert allowed(con, ONE, NOW + MINUTE)
    row = authz.challenge_for_account(con, challenge.id, TWO)
    assert row["verified_at"] is None and row["cancelled_at"] is None


def test_a_published_proof_closes_another_holders_presence(con):
    claim(con, ONE)
    _challenge, proved = dns_proof(con, TWO, moment=NOW + MINUTE)
    assert proved.recorded
    assert not allowed(con, ONE, NOW + MINUTE) and allowed(con, TWO, NOW + MINUTE)
    closed = [r for r in authz.list_authorizations(con) if r["account"] == ONE]
    assert closed[0]["revoked_at"] == (NOW + MINUTE).isoformat()
    # Its agent goes on sending, and is refused as held from then on.
    assert claim(con, ONE, moment=NOW + 15 * MINUTE).code == "address_held"


def test_a_published_proof_closes_another_workspaces_report_proof(con):
    second = db.create_workspace(con, "second")
    host_id, _ = store.add_host(con, "box", workspace_id=second)
    document = json.dumps({"interface_addresses": {"addresses": [
        {"interface": "eth0", "family": "v4", "address": V4}]}})
    assert authz.record_agent_proof(con, host_id, V4, document, now=NOW).recorded
    _challenge, proved = dns_proof(con, ONE, moment=NOW + MINUTE)
    assert proved.recorded
    assert not allowed(con, authz.account_for_workspace(second), NOW + MINUTE)


def test_a_refused_published_proof_closes_nothing(con):
    """Held by a published proof as well as by presence: the verify is
    refused, and the presence it would have closed stays."""
    claim(con, ONE)
    first, held = dns_proof(con, ONE)
    assert held.recorded
    _challenge, refused = dns_proof(con, TWO, moment=NOW + MINUTE, also=[first.token])
    assert refused.code == "address_held"
    held_by_one = authz.live_for_account(con, ONE, now=NOW + MINUTE)
    assert sorted(r["method"] for r in held_by_one) == sorted(["agent", DNS])


def test_our_own_fleets_proofs_close_nothing_and_are_never_closed(con):
    claim(con, ONE)
    _challenge, ours = dns_proof(con, authz.DEFAULT_ACCOUNT, moment=NOW + MINUTE)
    assert ours.recorded and allowed(con, ONE, NOW + MINUTE)


def test_a_published_proof_whose_record_is_gone_does_not_hold_the_address(con):
    """The reverse zone's keeper now holds only the new token: the earlier
    holder's proof is read again at the new verify and ends."""
    _first, held = dns_proof(con, ONE)
    assert held.recorded
    _challenge, proved = dns_proof(con, TWO, moment=NOW + MINUTE)
    assert proved.recorded
    assert not allowed(con, ONE, NOW + MINUTE) and allowed(con, TWO, NOW + MINUTE)


def test_a_holder_whose_evidence_gets_no_answer_keeps_the_address(con):
    """No answer is not no file: the daily reading decides it, not a
    stranger's verify."""
    started = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, account=ONE, now=NOW)
    assert authz.verify_proof(con, started.id, now=NOW,
                              fetcher=lambda url: started.token).recorded

    late = authz.start_proof(con, V4, DNS, account=TWO, now=NOW + MINUTE)

    def resolver(name):
        return [late.token]

    def fetcher(url):
        raise authz.ProofError("could not read the token file: TimeoutError")

    result = authz.verify_proof(con, late.id, now=NOW + MINUTE,
                                resolver=resolver, fetcher=fetcher)
    assert result.code == "address_held"
    assert allowed(con, ONE, NOW + MINUTE)


def test_a_published_proof_holds_the_address_against_another_instances_presence(con):
    _challenge, proved = dns_proof(con, ONE)
    assert proved.recorded
    assert claim(con, TWO).code == "address_held"


def test_an_instance_renews_its_own_address_by_another_way(con):
    claim(con, ONE)
    _challenge, proved = dns_proof(con, ONE)
    assert proved.recorded
    assert claim(con, ONE, moment=NOW + MINUTE).recorded


def test_a_revoke_frees_the_address(con):
    claim(con, ONE)
    authz.revoke(con, V4, now=NOW, account=ONE)
    assert claim(con, TWO, moment=NOW + MINUTE).recorded


def test_a_revoked_instance_frees_every_address_it_held(con):
    claim(con, ONE)
    authz.revoke_account(con, ONE, now=NOW)
    assert claim(con, TWO, moment=NOW + MINUTE).recorded


def test_a_lapse_frees_the_address(con):
    claim(con, ONE)
    assert claim(con, TWO, moment=NOW + HOUR - SECOND).code == "address_held"
    assert claim(con, TWO, moment=NOW + HOUR).recorded


def test_v4_and_v6_are_two_addresses_here_too(con):
    claim(con, ONE, address=V4)
    assert claim(con, TWO, address=V6).recorded


def test_a_workspaces_proof_does_not_make_an_address_held(con):
    """The rule is between instances. Our own fleet proving an address says
    nothing about who may hold it among instances."""
    _challenge, proved = dns_proof(con, authz.DEFAULT_ACCOUNT)
    assert proved.recorded
    assert claim(con, ONE).recorded


def test_the_instance_that_held_first_keeps_an_address_two_held_before_the_rule(con):
    """Two instances on one address can only come from a database written
    before the rule. The older proof keeps it and the younger one is not
    renewed, so the first instance never goes dark."""
    for account, expires in ((ONE, NOW + 50 * MINUTE), (TWO, NOW + 50 * MINUTE)):
        con.execute(
            "INSERT INTO authorizations (target, family, method, evidence,"
            " account, host_id, verified_at, expires_at)"
            " VALUES (?, 'v4', 'agent', '{}', ?, NULL, ?, ?)",
            (V4, account, (NOW - 10 * MINUTE).isoformat(), expires.isoformat()))
    con.commit()
    assert claim(con, ONE).recorded
    assert claim(con, TWO).code == "address_held"
    assert allowed(con, ONE, NOW + 55 * MINUTE)
    assert not allowed(con, TWO, NOW + 55 * MINUTE)


def test_two_instances_racing_for_one_address_end_with_one_holder(path, con, monkeypatch):
    """Two presences at once, from two processes. The first is held just
    before it writes, the second is let go meanwhile, and only then is the
    first let go. Checking and writing are one write transaction, so the
    second waits for the first's write and then sees the address held."""
    first_inside = threading.Event()
    let_first_go = threading.Event()
    real_record = authz._record

    def held_before_writing(connection, target, family, method, evidence,
                            account, *args, **kwargs):
        if account == ONE:
            first_inside.set()
            assert let_first_go.wait(10)
        return real_record(connection, target, family, method, evidence,
                           account, *args, **kwargs)

    monkeypatch.setattr(authz, "_record", held_before_writing)
    results = {}

    def present(account):
        own = db.connect(path)
        try:
            results[account] = claim(own, account)
        finally:
            own.close()

    first = threading.Thread(target=present, args=(ONE,))
    second = threading.Thread(target=present, args=(TWO,))
    first.start()
    assert first_inside.wait(10)
    second.start()
    time.sleep(0.3)  # the second's whole claim, had nothing held it back
    let_first_go.set()
    first.join(10)
    second.join(10)

    assert results[ONE].recorded
    assert not results[TWO].recorded and results[TWO].code == "address_held"
    assert [r["account"] for r in authz.list_authorizations(con)] == [ONE]


# ============================== an instance that signed up, never presence

@pytest.mark.parametrize("origin", [SIGNUP, None, "", "Invited", "invited ", 1])
def test_presence_refused_for_a_signup_instance(con, origin):
    """Refused by the registry itself, the way a workspace account is: the
    route checks first, so reaching this is a mistake and it is loud."""
    with pytest.raises(ValueError):
        claim(con, ONE, origin=origin)
    assert authz.list_authorizations(con) == []


def test_a_signup_instance_proves_by_dns_txt(con):
    _challenge, proved = dns_proof(con, ONE)
    assert proved.recorded and allowed(con, ONE, NOW)


def test_only_invited_proves_by_presence():
    assert (authz.ORIGIN_INVITED, authz.ORIGIN_SIGNUP) == (INVITED, SIGNUP)
    assert authz.proves_by_presence(INVITED)
    assert set(authz.ORIGINS) == {INVITED, SIGNUP}
    for origin in (SIGNUP, None, "", "INVITED", b"invited"):
        assert not authz.proves_by_presence(origin)


# ======================================================= the exclusion list

def test_excluding_closes_every_live_proof_and_every_proof_in_progress(con):
    claim(con, ONE)
    _challenge, proved = dns_proof(con, authz.DEFAULT_ACCOUNT)
    started = authz.start_proof(con, V4, DNS, account=TWO, now=NOW)
    added, closed = authz.exclude(con, V4, now=NOW)
    assert added and closed == 2
    assert not allowed(con, ONE, NOW) and not allowed(con, authz.DEFAULT_ACCOUNT, NOW)
    assert authz.challenge_for_account(con, started.id, TWO)["cancelled_at"]
    # Another address is untouched.
    assert claim(con, ONE, address=OTHER_V4).recorded


def test_an_excluded_address_is_refused_at_presence_for_every_instance(con):
    authz.exclude(con, V4, now=NOW)
    for account in (ONE, TWO, authz.account_for_instance(99)):
        result = claim(con, account, moment=NOW + MINUTE)
        assert not result.recorded and result.code == "target_refused"
    assert authz.list_authorizations(con) == []


@pytest.mark.parametrize("account", [ONE, authz.DEFAULT_ACCOUNT,
                                     authz.account_for_workspace(2)])
def test_an_excluded_address_cannot_be_started(con, account):
    authz.exclude(con, V4, now=NOW)
    with pytest.raises(authz.TargetError):
        authz.start_proof(con, V4, DNS, account=account, now=NOW)
    assert authz.list_challenges(con) == []


def test_an_excluded_address_is_refused_at_verify_and_never_fetched(con):
    """A challenge left open beside an exclusion, which `exclude` never
    leaves, is still refused, and nothing is sent to the address."""
    started = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, account=ONE, now=NOW)
    con.execute("INSERT INTO authz_exclusions (target, family, added_at)"
                " VALUES (?, 'v4', ?)", (V4, NOW.isoformat()))
    con.commit()
    fetched = []
    result = authz.verify_proof(con, started.id, now=NOW,
                                fetcher=lambda url: fetched.append(url) or started.token)
    assert not result.recorded and result.code == "target_refused"
    assert fetched == []
    assert authz.list_authorizations(con) == []


def test_an_exclusion_added_while_the_evidence_is_read_wins(path, con):
    started = authz.start_proof(con, V4, DNS, account=ONE, now=NOW)

    def resolver(name):
        other = db.connect(path)
        try:
            authz.exclude(other, V4, now=NOW)
        finally:
            other.close()
        return [started.token]

    result = authz.verify_proof(con, started.id, now=NOW, resolver=resolver)
    assert not result.recorded
    assert not allowed(con, ONE, NOW)


def test_an_excluded_address_is_not_proved_by_our_own_agents_either(con):
    host_id, _ = store.add_host(con, "box")
    authz.exclude(con, V4, now=NOW)
    document = json.dumps({"interface_addresses": {"addresses": [
        {"interface": "eth0", "family": "v4", "address": V4}]}})
    assert not authz.record_agent_proof(con, host_id, V4, document, now=NOW).recorded
    assert authz.list_authorizations(con) == []


def test_the_gate_refuses_an_excluded_address_even_beside_a_live_row(con):
    """Belt and braces: a live row and an exclusion can only meet if a row
    was written by hand. The gate refuses it, in the words it uses for an
    address nobody proved, and a snapshot leaves it out."""
    claim(con, ONE)
    con.execute("INSERT INTO authz_exclusions (target, family, added_at)"
                " VALUES (?, 'v4', ?)", (V4, NOW.isoformat()))
    con.commit()
    decision = authz.may_probe(con, V4, now=NOW, account=ONE)
    nobody = authz.may_probe(con, OTHER_V4, now=NOW, account=ONE)
    assert not decision.allowed
    assert decision.reason.replace(V4, "X") == nobody.reason.replace(OTHER_V4, "X")
    assert authz.build_snapshot(con, [V4], now=NOW, account=ONE).targets == {}


def test_a_published_proof_is_not_renewed_once_excluded(con):
    _challenge, proved = dns_proof(con, ONE)
    con.execute("INSERT INTO authz_exclusions (target, family, added_at)"
                " VALUES (?, 'v4', ?)", (V4, NOW.isoformat()))
    con.commit()
    renewal = authz.renew_published(con, now=NOW + 24 * DAY,
                                    resolver=lambda name: pytest.fail("read"))
    assert renewal["renewed"] == []


def test_taking_an_address_off_restores_nothing(con):
    claim(con, ONE)
    authz.exclude(con, V4, now=NOW)
    assert authz.unexclude(con, V4, now=NOW + MINUTE)
    assert not allowed(con, ONE, NOW + MINUTE)
    # A new proof is needed, and then it is probed again.
    assert claim(con, ONE, moment=NOW + 2 * MINUTE).recorded
    assert allowed(con, ONE, NOW + 2 * MINUTE)


def test_an_address_excluded_twice_is_one_entry_and_off_once(con):
    assert authz.exclude(con, V4, now=NOW) == (True, 0)
    assert authz.exclude(con, V4, now=NOW + MINUTE) == (False, 0)
    assert len(authz.list_exclusions(con)) == 1
    assert authz.unexclude(con, V4, now=NOW + 2 * MINUTE)
    assert not authz.unexclude(con, V4, now=NOW + 3 * MINUTE)
    with pytest.raises(sqlite3.IntegrityError):
        for _ in range(2):
            con.execute("INSERT INTO authz_exclusions (target, family, added_at)"
                        " VALUES (?, 'v4', ?)", (V4, NOW.isoformat()))


def test_the_list_keeps_what_was_taken_off_as_the_record(con):
    authz.exclude(con, V4, now=NOW)
    authz.unexclude(con, V4, now=NOW + MINUTE)
    authz.exclude(con, V4, now=NOW + 2 * MINUTE)
    rows = authz.list_exclusions(con)
    assert [(r["target"], r["removed_at"] is None) for r in rows] == [(V4, True), (V4, False)]
    assert authz.active_exclusion(con, V4)["added_at"] == (NOW + 2 * MINUTE).isoformat()
    assert authz.active_exclusion(con, OTHER_V4) is None


@pytest.mark.parametrize("address", ["10.0.0.1", "not an address", V4 + "%eth0"])
def test_only_an_address_that_could_be_probed_is_excluded(con, address):
    with pytest.raises(authz.TargetError):
        authz.exclude(con, address, now=NOW)
    assert authz.list_exclusions(con) == []


def test_an_address_is_excluded_in_one_spelling(con):
    authz.exclude(con, "2606:50C0:8000:0000:0000:0000:0000:0153", now=NOW)
    assert claim(con, ONE, address=V6).code == "target_refused"


# ============================= the proofs stored on the day this lands
#
# Nothing is rewritten. The gate reads a proof by presence as ending an hour
# after its last renewal whatever expiry it carries, so a row written under
# the week, before this or by the old build between a deploy's copy and its
# restart, gets its hour all the same.

def stored(con, address, account, method, verified, expires, host=None):
    """A row as the build before this wrote it, straight into the table."""
    cur = con.execute(
        "INSERT INTO authorizations (target, family, method, evidence, account,"
        " host_id, verified_at, expires_at) VALUES (?, 'v4', ?, '{}', ?, ?, ?, ?)",
        (address, method, account, host, verified, expires))
    con.commit()
    return cur.lastrowid


def test_a_six_day_old_presence_proof_is_not_probed_when_this_lands(con):
    stored(con, V4, ONE, "agent", (NOW - 6 * DAY).isoformat(), (NOW + DAY).isoformat())
    assert not allowed(con, ONE, NOW)
    assert authz.live_for_account(con, ONE, now=NOW) == []
    assert authz.build_snapshot(con, [V4], now=NOW, account=ONE).targets == {}
    assert authz.live_proof_counts(con, now=NOW) == {}
    # And the sweep writes it off, so the listing says so too.
    assert authz.sweep(con, now=NOW)["expired"] == [V4]


def test_a_week_written_in_the_deploy_window_is_read_as_an_hour(con):
    """The old ingest answers until the restart, after the new code is on
    the box, and writes the week it knows."""
    stored(con, V4, ONE, "agent", NOW.isoformat(), (NOW + 7 * DAY).isoformat())
    assert allowed(con, ONE, NOW + HOUR - SECOND)
    assert not allowed(con, ONE, NOW + HOUR)
    snapshot = authz.build_snapshot(con, [V4], now=NOW, account=ONE)
    assert snapshot.targets == {V4: NOW + HOUR}
    row = authz.live_for_account(con, ONE, now=NOW)[0]
    assert authz.live_until(row) == NOW + HOUR


def test_a_running_agents_old_row_is_renewed_in_place(con):
    old = stored(con, V4, ONE, "agent", (NOW - 10 * MINUTE).isoformat(),
                 (NOW + 7 * DAY).isoformat())
    renewed = claim(con, ONE, moment=NOW + 5 * MINUTE)
    assert renewed.recorded and renewed.authorization_id == old
    assert allowed(con, ONE, NOW + HOUR)
    assert not allowed(con, ONE, NOW + HOUR + 5 * MINUTE)


def test_published_proofs_and_our_own_agents_keep_their_lifetimes(con):
    host_id, _ = store.add_host(con, "ours")
    stored(con, V4, ONE, DNS, (NOW - 6 * DAY).isoformat(), (NOW + 24 * DAY).isoformat())
    stored(con, OTHER_V4, authz.DEFAULT_ACCOUNT, "agent", (NOW - 6 * DAY).isoformat(),
           (NOW + DAY).isoformat(), host=host_id)
    assert allowed(con, ONE, NOW)
    assert allowed(con, authz.DEFAULT_ACCOUNT, NOW, address=OTHER_V4)


@pytest.mark.parametrize("verified, expires", [
    ("a while ago", (NOW + DAY).isoformat()),
    ((NOW - 10 * MINUTE).isoformat(), "soon"),
])
def test_a_presence_row_that_cannot_be_read_is_never_live(con, verified, expires):
    stored(con, V4, ONE, "agent", verified, expires)
    assert not allowed(con, ONE, NOW)
    assert authz.live_for_account(con, ONE, now=NOW) == []


def test_a_new_database_starts_with_the_list(path):
    fresh = db.connect(path)
    try:
        db.init(fresh)
        authz.init(fresh)
        assert authz.list_exclusions(fresh) == []
    finally:
        fresh.close()


# ===================================== the command run on the box

@pytest.fixture()
def cli(path, con, tmp_path, monkeypatch):
    """`python -m app.authz_cli ...` against this test's database, with no
    environment file read from the machine running the tests."""
    from app import authz_cli, envfile
    monkeypatch.setenv(db.DB_ENV, path)
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(tmp_path / "absent.env"))
    return lambda *argv: authz_cli.main(list(argv))


def test_cli_exclude_closes_the_proofs_and_says_so(cli, con, capsys):
    claim(con, ONE)
    assert cli("exclude", V4) == 0
    out = capsys.readouterr().out
    assert f"{V4} is excluded, 1 proof of it closed" in out
    assert not allowed(con, ONE, NOW)


def test_cli_exclude_twice_says_since_when(cli, con, capsys):
    cli("exclude", V4)
    added = authz.active_exclusion(con, V4)["added_at"]
    capsys.readouterr()
    assert cli("exclude", V4) == 0
    assert f"{V4} was already excluded, since {added}" in capsys.readouterr().out


def test_cli_unexclude_restores_nothing_and_says_so(cli, con, capsys):
    cli("exclude", V4)
    capsys.readouterr()
    assert cli("unexclude", V4) == 0
    assert "new proof" in capsys.readouterr().out
    assert authz.active_exclusion(con, V4) is None
    assert cli("unexclude", V4) == 1
    assert f"{V4} is not excluded" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["exclude", "unexclude"])
def test_cli_refuses_what_is_not_an_address(cli, con, capsys, command):
    assert cli(command, "10.0.0.1") == 1
    assert "not a globally routable" in capsys.readouterr().err
    assert authz.list_exclusions(con) == []


def test_cli_list_shows_what_is_excluded(cli, con, capsys):
    cli("exclude", V4)
    capsys.readouterr()
    assert cli("list") == 0
    out = capsys.readouterr().out
    assert "excluded:" in out and V4 in out
