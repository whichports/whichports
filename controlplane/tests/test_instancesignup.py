"""Open signup for the self-hosted beta: the rules and what is kept
(`app/instancesignup.py`).

The installer signs up with an address and a claim it keeps on the server,
our API mails the address eight digits, and the claim with those digits
collects one instance. These go at the rules the way a stranger would:
twice, after a day, past every cap, closed, racing, guessing, and with an
address that already has an instance. Every address is on a reserved
example domain (RFC 2606).
"""
import dataclasses
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app import authz, db, instances, instancesignup, proberapi

NOW = datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc)
ANN = "ann@example.org"
BOB = "bob@example.net"
V4 = "185.199.108.153"


@pytest.fixture()
def con():
    connection = db.connect(":memory:")
    for module in (db, authz, instances, instancesignup, proberapi):
        module.init(connection)
    yield connection
    connection.close()


@pytest.fixture()
def opened(monkeypatch):
    """Signup open, and the cap on live instances out of the way, so a test
    meets the cap it is about. The live cap has its own test."""
    monkeypatch.setenv(instancesignup.MODE_ENV, "open")
    monkeypatch.setattr(instancesignup, "LIVE_SIGNUP_INSTANCES", 1000)


@dataclasses.dataclass(frozen=True)
class Signup:
    """What one signup answered, with the claim the installer keeps."""
    answer: str
    code: str | None
    tell_owner: bool
    claim: str


def ask(con, email=ANN, now=NOW, claim=None):
    """One signup as the installer makes it: an address and a fresh claim."""
    claim = claim or secrets.token_hex(32)
    asked = instancesignup.request_code(con, email, claim, now)
    return Signup(asked.answer, asked.code, asked.tell_owner, claim)


def collect(con, signup, code=None, now=NOW):
    """The claim of `signup` with a code, its own mailed one unless given."""
    return instancesignup.collect(con, signup.claim,
                                  signup.code if code is None else code, now)


def made(con, email=ANN, now=NOW):
    """An instance signed up and collected: its keys, once."""
    return collect(con, ask(con, email, now), now=now).issued


def other_than(code):
    """A code of the right shape that is not this one."""
    return f"{(int(code) + 1) % 10 ** 8:08d}"


def address(n):
    return f"person{n}@example.org"


def kept_rows(con, table):
    return con.execute(f"SELECT * FROM {table}").fetchall()


def claims_of(con, email):
    return con.execute("SELECT COUNT(*) FROM instance_signup_claims WHERE email = ?",
                       (email,)).fetchone()[0]


TABLES = ("instance_signups", "instance_signup_claims", "instance_signup_days")


# ================================================================ the switch

@pytest.mark.parametrize("value,expected", [
    (None, "closed"), ("", "closed"), ("closed", "closed"), ("yes", "closed"),
    ("opened", "closed"), ("open now", "closed"), ("1", "closed"),
    ("open", "open"), ("  OPEN ", "open"), ("Open", "open"),
])
def test_signup_closed_unless_it_reads_open(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv(instancesignup.MODE_ENV, raising=False)
    else:
        monkeypatch.setenv(instancesignup.MODE_ENV, value)
    assert instancesignup.mode() == expected


def test_closed_sends_nothing_and_keeps_nothing(con, monkeypatch):
    monkeypatch.delenv(instancesignup.MODE_ENV, raising=False)
    outcome = ask(con)
    assert outcome.answer == "closed"
    assert outcome.code is None
    for table in TABLES:
        assert kept_rows(con, table) == []


def test_closing_ends_no_instance(con, opened, monkeypatch):
    issued = made(con)
    monkeypatch.setenv(instancesignup.MODE_ENV, "closed")
    assert ask(con, BOB).answer == "closed"
    assert instances.by_name(con, issued.instance.name).revoked_at is None


# ============================================== the same answer, whoever asks

def test_same_answer_for_new_waiting_and_instance_address(con, opened):
    new = ask(con)
    assert (new.answer, new.code is not None) == ("sent", True)
    waiting = ask(con)
    assert (waiting.answer, waiting.code) == ("sent", None)
    collect(con, new)
    with_instance = ask(con, now=NOW + timedelta(hours=25))
    assert (with_instance.answer, with_instance.code) == ("sent", None)


def test_a_signup_stores_a_claim_for_every_address_it_takes(con, opened):
    """A claim kept for some addresses and not others would say, at its
    first collect, which addresses have an instance or a code."""
    collect(con, ask(con, "taken@example.org"))
    by_hand = made(con, "revoked@example.org")
    instances.revoke(con, by_hand.instance.name, now=NOW)
    ask(con, "waiting@example.org")
    for email in ("new@example.org", "waiting@example.org",
                  "taken@example.org", "revoked@example.org"):
        before = claims_of(con, email)
        assert ask(con, email, now=NOW + timedelta(minutes=1)).answer == "sent"
        assert claims_of(con, email) == before + 1, email


def test_the_days_count_moves_the_same_for_every_address(con, opened, monkeypatch):
    """The day's cap is what everybody meets, so it moves by one for every
    new claim, whatever the address's state. Counted only when a mail went,
    it would say which addresses got one: a stranger signs up with the
    address, then with their own, and counts to full_today."""
    monkeypatch.setattr(instancesignup, "SIGNUPS_PER_DAY", 1000)
    collect(con, ask(con, "taken@example.org"))
    by_hand = made(con, "revoked@example.org")
    instances.revoke(con, by_hand.instance.name, now=NOW)
    ask(con, "waiting@example.org")
    for _ in range(2):
        ask(con, "crowded@example.org")
    for email in ("new@example.org", "waiting@example.org", "taken@example.org",
                  "revoked@example.org", "crowded@example.org", "crowded@example.org"):
        before = instancesignup.today(con, NOW)["signups"]
        ask(con, email, now=NOW + timedelta(minutes=1))
        assert instancesignup.today(con, NOW)["signups"] == before + 1, email
    # The same claim again is the same installer, and counts nothing.
    again = ask(con, "repeat@example.org")
    before = instancesignup.today(con, NOW)["signups"]
    ask(con, "repeat@example.org", claim=again.claim)
    assert instancesignup.today(con, NOW)["signups"] == before


def test_one_code_per_address_per_day(con, opened, monkeypatch):
    codes = iter(["11111111", "22222222"])
    monkeypatch.setattr(instancesignup, "new_code", lambda: next(codes))
    first = ask(con)
    late = ask(con, now=NOW + timedelta(hours=23))
    assert late.code is None
    later = ask(con, now=NOW + timedelta(hours=24, seconds=1))
    assert (first.code, later.code) == ("11111111", "22222222")
    # The first code died when its 24 hours passed. The address's code is
    # the one mailed last, and a live claim of the address collects with it.
    then = NOW + timedelta(hours=24, seconds=2)
    assert collect(con, late, "11111111", then).answer == "wrong"
    assert collect(con, late, "22222222", then).answer == "made"


def test_an_address_is_one_address_however_it_is_typed(con, opened):
    assert ask(con, "Ann@Example.org").code is not None
    assert ask(con, "  ann@example.ORG ").code is None


def test_an_address_that_is_not_one_is_refused_before_anything(con, opened):
    with pytest.raises(instancesignup.InvalidEmail):
        ask(con, "not an address")
    for table in TABLES:
        assert kept_rows(con, table) == []


@pytest.mark.parametrize("claim", [
    None, "", 5, "abc", "A" * 64, "g" * 64, "a" * 63, "a" * 65,
    "a" * 64 + "\n", " " + "a" * 63,
])
def test_a_claim_that_is_not_one_is_refused_before_anything(con, opened, claim):
    with pytest.raises(instancesignup.InvalidClaim):
        instancesignup.request_code(con, ANN, claim, NOW)
    for table in TABLES:
        assert kept_rows(con, table) == []


def test_the_same_claim_twice_is_one_claim(con, opened):
    first = ask(con)
    again = ask(con, claim=first.claim, now=NOW + timedelta(minutes=1))
    assert (again.answer, again.code) == ("sent", None)
    assert claims_of(con, ANN) == 1


# ===================================================================== caps

def test_spent_cap_answers_full_and_mails_him_once(con, opened):
    for n in range(instancesignup.SIGNUPS_PER_DAY):
        assert ask(con, address(n)).answer == "sent"
    full = ask(con, address(999))
    assert (full.answer, full.code, full.tell_owner) == ("full_today", None, True)
    again = ask(con, address(998), now=NOW + timedelta(minutes=5))
    assert (again.answer, again.tell_owner) == ("full_today", False)
    # An address that already has a code waiting is told the same: full.
    assert ask(con, address(0)).answer == "full_today"
    # A full answer keeps no claim, so the installer keeps none either.
    assert claims_of(con, address(999)) == 0
    assert claims_of(con, address(0)) == 1
    tomorrow = NOW.replace(hour=0) + timedelta(days=1)
    assert ask(con, address(999), now=tomorrow).answer == "sent"


def test_a_day_of_new_instances_is_capped(con, opened, monkeypatch):
    # One code more than the day's instances, so the codes' own cap, which
    # is lower, is out of the way of the cap this is about.
    monkeypatch.setattr(instancesignup, "SIGNUPS_PER_DAY", 1000)
    signups = [ask(con, address(n))
               for n in range(instancesignup.INSTANCES_PER_DAY + 1)]
    for signup in signups[:-1]:
        assert collect(con, signup).answer == "made"
    over = collect(con, signups[-1])
    assert (over.answer, over.issued, over.tell_owner) == ("full_today", None, True)
    assert ask(con, address(500)).answer == "full_today"
    # Nothing was spent: the code works tomorrow, inside its 24 hours.
    tomorrow = NOW.replace(hour=0) + timedelta(days=1, minutes=1)
    assert collect(con, signups[-1], now=tomorrow).answer == "made"


def test_the_live_signup_instances_are_capped_and_revoked_ones_free_room(con, opened, monkeypatch):
    monkeypatch.setattr(instancesignup, "LIVE_SIGNUP_INSTANCES", 2)
    one = made(con, address(1))
    made(con, address(2))
    # An invited instance is not counted.
    instances.add(con, "invited-one", now=NOW, origin=authz.ORIGIN_INVITED)
    waiting = ask(con, address(3), now=NOW)
    # One plain refusal that no day ends, never "tomorrow".
    assert (waiting.answer, waiting.tell_owner) == ("full", True)
    instances.revoke(con, one.instance.name, now=NOW)
    assert ask(con, address(3), now=NOW).answer == "sent"


def test_a_spent_live_cap_is_full_and_not_full_today(con, opened, monkeypatch):
    """Both caps spent: the live one answers, since tomorrow ends nothing."""
    monkeypatch.setattr(instancesignup, "LIVE_SIGNUP_INSTANCES", 1)
    monkeypatch.setattr(instancesignup, "INSTANCES_PER_DAY", 1)
    first = ask(con, address(1))
    later = ask(con, address(2))
    collect(con, first)
    assert ask(con, address(3)).answer == "full"
    assert collect(con, later).answer == "full"


def test_collect_checks_every_cap_again(con, opened, monkeypatch):
    """A code mailed while there was room makes nothing once there is none,
    and spends nothing: no wrong try, and the code still works later."""
    signup = ask(con, BOB)
    monkeypatch.setenv(instancesignup.MODE_ENV, "closed")
    assert collect(con, signup).answer == "closed"
    monkeypatch.setenv(instancesignup.MODE_ENV, "open")

    monkeypatch.setattr(instancesignup, "LIVE_SIGNUP_INSTANCES", 1)
    first = made(con, ANN)
    assert collect(con, signup).answer == "full"
    assert collect(con, signup, other_than(signup.code)).answer == "full"

    monkeypatch.setattr(instancesignup, "LIVE_SIGNUP_INSTANCES", 1000)
    monkeypatch.setattr(instancesignup, "INSTANCES_PER_DAY", 1)
    assert collect(con, signup).answer == "full_today"

    monkeypatch.setattr(instancesignup, "INSTANCES_PER_DAY", 10)
    instances.revoke(con, first.instance.name, now=NOW)
    wrong = con.execute("SELECT wrong FROM instance_signup_claims WHERE email = ?",
                        (BOB,)).fetchone()[0]
    assert wrong == 0
    assert collect(con, signup).answer == "made"
    assert instances.list_all(con)[-1].origin == authz.ORIGIN_SIGNUP


# ============================================================ codes and claims

def test_a_code_is_eight_random_digits():
    codes = [instancesignup.new_code() for _ in range(200)]
    assert all(re.fullmatch(r"[0-9]{8}", code) for code in codes)
    assert len(set(codes)) > 190


def test_the_right_code_with_a_live_claim_gives_the_line_once(con, opened):
    signup = ask(con)
    first = collect(con, signup)
    assert first.answer == "made" and not first.again
    issued = first.issued
    assert instances.instance_for_key(con, issued.api_key, "api").name == issued.instance.name
    assert instances.instance_for_key(con, issued.proof_key, "proof").name == issued.instance.name
    # The claim's day is over: nothing more comes for it, with any code.
    after = NOW + instancesignup.CLAIM_TTL + timedelta(seconds=1)
    assert collect(con, signup, now=after).answer == "wrong"
    assert len(instances.list_all(con)) == 1


@pytest.mark.parametrize("claim", [None, "", "x" * 5000, 5, "not-a-claim", "A" * 64])
def test_a_claim_nobody_made_answers_wrong(con, opened, claim):
    signup = ask(con)
    assert instancesignup.collect(con, claim, signup.code, NOW).answer == "wrong"
    assert instancesignup.collect(con, secrets.token_hex(32), signup.code,
                                  NOW).answer == "wrong"


@pytest.mark.parametrize("code", [None, "", 12345678, "1234567", "123456789",
                                  "abcdefgh", " 1234567", "1234567\n"])
def test_a_code_of_the_wrong_shape_answers_wrong(con, opened, code):
    signup = ask(con)
    assert instancesignup.collect(con, signup.claim, code, NOW).answer == "wrong"
    assert collect(con, signup).answer == "made"


def test_every_failure_to_collect_answers_wrong(con, opened):
    """One word for every way it does not work, so a collect never says
    which addresses have an instance, a code, or neither."""
    answers = set()
    live = ask(con, "live@example.org")
    answers.add(collect(con, live, other_than(live.code)).answer)
    old = ask(con, "old@example.org")
    answers.add(collect(con, old, now=NOW + timedelta(hours=24)).answer)
    taken = made(con, "taken@example.org", now=NOW - timedelta(days=2))
    assert taken is not None
    no_code = ask(con, "taken@example.org")
    assert no_code.code is None
    answers.add(collect(con, no_code, "12345678").answer)
    worn = ask(con, "worn@example.org")
    for _ in range(instancesignup.WRONG_CODES_PER_CLAIM):
        collect(con, worn, other_than(worn.code))
    answers.add(collect(con, worn).answer)
    answers.add(instancesignup.collect(con, secrets.token_hex(32), "12345678",
                                       NOW).answer)
    assert answers == {"wrong"}


def test_five_wrong_codes_end_a_claim(con, opened):
    first = ask(con)
    second = ask(con, now=NOW + timedelta(minutes=1))
    for _ in range(instancesignup.WRONG_CODES_PER_CLAIM):
        assert collect(con, first, other_than(first.code)).answer == "wrong"
    # The right code after five wrong ones: the claim answers wrong to
    # everything now.
    assert collect(con, first).answer == "wrong"
    # The tries are the claim's: another claim of the address collects.
    assert collect(con, second, first.code).answer == "made"


def test_three_claims_per_address_a_day(con, opened):
    """So whoever guesses at somebody's address has 15 tries a day, at one
    chance in a hundred million each."""
    signups = [ask(con, now=NOW + timedelta(minutes=n)) for n in range(4)]
    assert [s.answer for s in signups] == ["sent"] * 4
    assert claims_of(con, ANN) == instancesignup.CLAIMS_PER_ADDRESS == 3
    code = signups[0].code
    # The fourth was kept nowhere, so the right code does nothing for it.
    assert collect(con, signups[3], code).answer == "wrong"
    tomorrow = NOW + timedelta(hours=24, minutes=4)
    fresh = ask(con, now=tomorrow)
    assert claims_of(con, ANN) == 1 and fresh.code is not None
    assert collect(con, fresh, now=tomorrow).answer == "made"


def test_a_second_install_with_one_address_collects_with_its_code(con, opened):
    first = ask(con)
    second = ask(con, now=NOW + timedelta(hours=1))
    assert second.code is None
    assert collect(con, second, first.code, NOW + timedelta(hours=1)).answer == "made"
    # The code is spent: the address has its one live instance.
    assert collect(con, first, now=NOW + timedelta(hours=1)).answer == "wrong"
    assert len(instances.list_all(con)) == 1


def test_a_recollect_within_the_day_reissues_and_ends_the_first_keys(con, opened):
    """A line lost between the answer and the write is mended by running the
    line again inside the claim's day, which is the day the installer keeps
    its claim file, and never two live key sets."""
    signup = ask(con)
    one = collect(con, signup, now=NOW + timedelta(hours=2)).issued
    within = NOW + instancesignup.CLAIM_TTL - timedelta(seconds=1)
    again = collect(con, signup, "00000000", within)
    assert again.answer == "made" and again.again
    two = again.issued
    assert two.instance.name == one.instance.name
    assert {two.api_key, two.proof_key}.isdisjoint({one.api_key, one.proof_key})
    assert instances.instance_for_key(con, one.api_key, "api") is None
    assert instances.instance_for_key(con, one.proof_key, "proof") is None
    assert instances.instance_for_key(con, two.api_key, "api").name == one.instance.name
    # A recollect makes nothing: one instance, counted once today.
    assert len(instances.list_all(con)) == 1
    assert instancesignup.today(con, NOW)["made"] == 1
    after = NOW + instancesignup.CLAIM_TTL + timedelta(seconds=1)
    assert collect(con, signup, now=after).answer == "wrong"


def test_a_recollect_of_a_revoked_instance_answers_wrong(con, opened):
    signup = ask(con)
    issued = collect(con, signup).issued
    instances.revoke(con, issued.instance.name, now=NOW)
    assert collect(con, signup, now=NOW + timedelta(minutes=1)).answer == "wrong"


def test_done_ends_the_claim(con, opened):
    signup = ask(con)
    collect(con, signup)
    assert instancesignup.done(con, signup.claim, NOW) is True
    assert claims_of(con, ANN) == 0
    assert collect(con, signup, now=NOW + timedelta(minutes=1)).answer == "wrong"
    # A claim that never collected stays to its 24 hours, so done cannot
    # hand whoever guesses at an address a fresh claim and five more tries.
    waiting = ask(con, BOB)
    assert instancesignup.done(con, waiting.claim, NOW) is False
    assert claims_of(con, BOB) == 1
    assert collect(con, waiting).answer == "made"
    for claim in (None, "", "zz", secrets.token_hex(32)):
        assert instancesignup.done(con, claim, NOW) is False


def test_two_collects_racing_make_one_instance(tmp_path, monkeypatch):
    """Two installs with one address type its code at once. The live cap is
    out of the way, so what stops the second is the code being spent."""
    monkeypatch.setenv(instancesignup.MODE_ENV, "open")
    monkeypatch.setattr(instancesignup, "LIVE_SIGNUP_INSTANCES", 1000)
    path = str(tmp_path / "cp.db")
    setup = db.connect(path)
    for module in (db, authz, instances, instancesignup):
        module.init(setup)
    first = ask(setup)
    second = ask(setup)
    setup.close()
    answers = []
    start = threading.Barrier(2)

    def collect_with(signup):
        own = db.connect(path)
        try:
            start.wait()
            answers.append(instancesignup.collect(own, signup.claim, first.code,
                                                  NOW).answer)
        finally:
            own.close()

    threads = [threading.Thread(target=collect_with, args=(s,)) for s in (first, second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(answers) == ["made", "wrong"]
    check = db.connect(path)
    assert len(instances.list_all(check)) == 1
    check.close()


# ============================================================ the instance

def test_one_live_instance_per_address(con, opened):
    issued = made(con)
    later = NOW + timedelta(days=2)
    assert ask(con, now=later).code is None
    # Ended unused by the sweep, the address is free again. One he revoked
    # by hand is not, while it is kept (the test below).
    instances.revoke(con, issued.instance.name, now=later, unused=True)
    assert ask(con, now=later).code is not None


def test_an_address_revoked_by_hand_answers_sent_and_gets_no_code_while_it_is_kept(con, opened):
    """He revokes an instance by hand for a reason, an abuse report say. Its
    address gets the answer every address gets and no mail, as long as the
    address is kept, 30 days after the revoke."""
    issued = made(con)
    instances.revoke(con, issued.instance.name, now=NOW + timedelta(days=1))
    again = ask(con, now=NOW + timedelta(days=2))
    assert (again.answer, again.code) == ("sent", None)
    instancesignup.sweep(con, NOW + timedelta(days=31, seconds=1))
    assert instances.contact_of(con, issued.instance.id) is None
    assert ask(con, now=NOW + timedelta(days=31, minutes=1)).code is not None


def test_an_address_whose_instance_ended_unused_may_sign_up_again(con, opened):
    made(con)
    assert instancesignup.sweep(con, NOW + timedelta(days=14, seconds=1))["ended"] == [ANN]
    assert ask(con, now=NOW + timedelta(days=14, minutes=1)).code is not None


def test_instance_name_holds_nothing_of_the_address(con, opened):
    names = set()
    for email in ("ann@example.org", "signup@example.net",
                  "a@b.example", "x.y+z@sub.example.com"):
        name = made(con, email).instance.name
        assert re.fullmatch(r"signup-[0-9a-f]{12}", name), name
        for part in re.split(r"[.@+]", email):
            if len(part) > 1:
                assert part not in name.removeprefix("signup-"), (part, name)
        names.add(name)
    assert len(names) == 4


def test_signup_instance_never_proves_by_presence(con, opened):
    instance = made(con).instance
    assert instance.origin == authz.ORIGIN_SIGNUP
    assert not instance.proves_by_presence
    with pytest.raises(ValueError):
        authz.record_presence_claim(con, instance.account, V4, [V4], now=NOW,
                                    origin=instance.origin)
    assert not authz.list_authorizations(con)


def test_the_instance_keeps_its_address_and_the_keys_only_as_hashes(con, opened):
    issued = made(con)
    assert instances.contact_of(con, issued.instance.id) == ANN
    stored = " ".join(str(v) for row in con.execute(
        "SELECT * FROM probe_instance_keys") for v in tuple(row))
    assert issued.api_key not in stored and issued.proof_key not in stored


# ============================================================ what is kept

def test_the_code_and_the_claim_are_kept_only_as_hashes(con, opened, monkeypatch):
    monkeypatch.setattr(instancesignup, "new_code", lambda: "48151623")
    signup = ask(con)
    stored = " ".join(str(v) for table in ("instance_signups", "instance_signup_claims")
                      for row in kept_rows(con, table) for v in tuple(row))
    assert "48151623" not in stored
    assert signup.claim not in stored
    assert ANN in stored


def test_waiting_codes_and_claims_deleted_by_the_sweep(con, opened):
    ask(con)
    ask(con, BOB, now=NOW + timedelta(hours=12))
    swept = instancesignup.sweep(con, NOW + timedelta(hours=24, seconds=1))
    assert (swept["codes"], swept["claims"]) == (1, 1)
    for table in ("instance_signups", "instance_signup_claims"):
        left = [row[0] for row in con.execute(f"SELECT email FROM {table}")]
        assert left == [BOB], table


def test_a_used_code_leaves_no_waiting_row(con, opened):
    made(con)
    assert kept_rows(con, "instance_signups") == []


def test_a_collected_claim_goes_with_its_day(con, opened):
    """One lifetime for a claim, collected or not: its 24 hours from the
    signup, or done."""
    made(con)
    instancesignup.sweep(con, NOW + instancesignup.CLAIM_TTL - timedelta(seconds=1))
    assert claims_of(con, ANN) == 1
    instancesignup.sweep(con, NOW + instancesignup.CLAIM_TTL + timedelta(seconds=1))
    assert claims_of(con, ANN) == 0


def test_address_deleted_30_days_after_revoke(con, opened):
    issued = made(con)
    revoked_at = NOW + timedelta(days=3)
    instances.revoke(con, issued.instance.name, now=revoked_at)
    instancesignup.sweep(con, revoked_at + timedelta(days=29, hours=23))
    assert instances.contact_of(con, issued.instance.id) == ANN
    instancesignup.sweep(con, revoked_at + timedelta(days=30, seconds=1))
    assert instances.contact_of(con, issued.instance.id) is None
    # The instance itself stays, as the record of who could probe what.
    assert instances.by_name(con, issued.instance.name) is not None


def test_a_live_instance_keeps_its_address(con, opened):
    issued = made(con)
    # Used the day before, so it is live on day 400.
    batch_for(con, issued, NOW + timedelta(days=399))
    instancesignup.sweep(con, NOW + timedelta(days=400))
    assert instances.by_name(con, issued.instance.name).revoked_at is None
    assert instances.contact_of(con, issued.instance.id) == ANN


# ====================================================== an unused instance
#
# A signup instance that has sent no batch and made no proof for 14 days is
# revoked by the sweep, decided 27 October 2026, and its address is told
# once. Signing up again gives a new one.

def batch_for(con, issued, when):
    proberapi.log_sent(con, issued.instance.id, "probe1", [V4], 2, when)


def proof_for(con, issued, when):
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT,
                                  account=issued.instance.account, now=when)
    con.execute("UPDATE authz_challenges SET verified_at = ? WHERE id = ?",
                (when.isoformat(), challenge.id))
    con.commit()


def test_an_unused_signup_instance_ends_after_14_days(con, opened):
    issued = made(con)
    early = instancesignup.sweep(con, NOW + timedelta(days=14) - timedelta(minutes=1))
    assert early["ended"] == []
    assert instances.by_name(con, issued.instance.name).revoked_at is None
    swept = instancesignup.sweep(con, NOW + timedelta(days=14, seconds=1))
    assert swept["ended"] == [ANN]
    assert instances.by_name(con, issued.instance.name).revoked_at is not None
    # Its address is kept like any revoked one's, for the abuse answer.
    assert instances.contact_of(con, issued.instance.id) == ANN
    assert instancesignup.sweep(con, NOW + timedelta(days=15))["ended"] == []


@pytest.mark.parametrize("used", [batch_for, proof_for])
def test_a_batch_or_a_proof_keeps_it_14_days_more(con, opened, used):
    issued = made(con)
    used(con, issued, NOW + timedelta(days=10))
    assert instancesignup.sweep(con, NOW + timedelta(days=14, seconds=1))["ended"] == []
    assert instancesignup.sweep(con, NOW + timedelta(days=24, seconds=1))["ended"] == [ANN]


def test_a_started_proof_that_proved_nothing_keeps_nothing(con, opened):
    issued = made(con)
    authz.start_proof(con, V4, authz.METHOD_DNS_TXT, account=issued.instance.account,
                      now=NOW + timedelta(days=10))
    assert instancesignup.sweep(con, NOW + timedelta(days=14, seconds=1))["ended"] == [ANN]


def test_an_invited_instance_never_ends_unused(con, opened):
    invited = instances.add(con, "invited-one", now=NOW, origin=authz.ORIGIN_INVITED)
    assert instancesignup.sweep(con, NOW + timedelta(days=400))["ended"] == []
    assert instances.by_name(con, invited.instance.name).revoked_at is None


def test_the_ended_mail_says_it_ended_and_signing_up_again_gives_a_new_one(monkeypatch):
    from app import betasignup, notify
    sent = []
    monkeypatch.setattr(notify, "send", lambda subject, body, config=None, html="":
                        sent.append((subject, body, html, config.to)) or (True, ""))
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example.net")
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", "owner@example.net")
    monkeypatch.setenv(betasignup.LANDING_ENV, "https://whichports.example")
    assert instancesignup.tell_ended([ANN, BOB]) == 2
    assert [to for *_rest, to in sent] == [ANN, BOB]
    subject, body, html, _to = sent[0]
    assert "ended" in subject.lower()
    assert "14 days" in body and "new one" in body
    assert "https://whichports.example/#docs-install" in body
    assert "https://whichports.example/#docs-install" in html and ">Install</a>" in html
    for words in (subject, body):
        assert "whpi_" not in words and "whpp_" not in words and "signup-" not in words


def test_no_ended_mail_without_the_landing_or_a_relay(monkeypatch):
    from app import betasignup, notify
    sent = []
    monkeypatch.setattr(notify, "send", lambda *a, **k: sent.append(a) or (True, ""))
    monkeypatch.delenv(betasignup.LANDING_ENV, raising=False)
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example.net")
    assert instancesignup.tell_ended([ANN]) == 0
    monkeypatch.setenv(betasignup.LANDING_ENV, "https://whichports.example")
    monkeypatch.delenv("WHICHPORTS_SMTP_HOST", raising=False)
    assert instancesignup.tell_ended([ANN]) == 0
    assert sent == []


def test_day_counts_hold_no_address_and_go_after_two_days(con, opened):
    made(con)
    columns = {row[1] for row in con.execute("PRAGMA table_info(instance_signup_days)")}
    assert columns == {"day", "signups", "made", "told_full"}
    instancesignup.sweep(con, NOW + timedelta(days=1))
    assert len(kept_rows(con, "instance_signup_days")) == 1
    instancesignup.sweep(con, NOW + timedelta(days=3))
    assert kept_rows(con, "instance_signup_days") == []


def test_works_on_a_bare_sqlite_connection(tmp_path, monkeypatch):
    """Rows read by position, so a connection without `sqlite3.Row` works
    the same (site tests open them so)."""
    monkeypatch.setenv(instancesignup.MODE_ENV, "open")
    path = str(tmp_path / "bare.db")
    setup = db.connect(path)
    for module in (db, authz, instances, instancesignup):
        module.init(setup)
    setup.close()
    bare = sqlite3.connect(path)
    try:
        signup = ask(bare)
        assert ask(bare).code is None
        assert collect(bare, signup).answer == "made"
        assert collect(bare, signup, now=NOW + timedelta(minutes=1)).again
        assert instancesignup.done(bare, signup.claim, NOW) is True
        instancesignup.sweep(bare, NOW + timedelta(days=3))
    finally:
        bare.close()


def test_init_is_idempotent(con):
    instancesignup.init(con)
    instancesignup.init(con)


def test_the_numbers_are_the_ones_the_spec_set():
    """docs/SPEC-open-beta.md, The code, its tries, lifetime and caps. A
    change is the owner's."""
    assert instancesignup.CODE_TTL == timedelta(hours=24)
    assert instancesignup.CLAIM_TTL == timedelta(hours=24)
    assert not hasattr(instancesignup, "RECOLLECT_FOR")
    assert instancesignup.WRONG_CODES_PER_CLAIM == 5
    assert instancesignup.CLAIMS_PER_ADDRESS == 3
    # Ten since 27 October: a stranger can spend the day's mails on other
    # people's addresses, and each is a mail through our relay. Since the
    # code's challenge of 28 October it counts every signup, mailed or not.
    assert instancesignup.SIGNUPS_PER_DAY == 10
    assert instancesignup.INSTANCES_PER_DAY == 10
    assert instances.CONTACT_KEPT_AFTER_REVOKE == timedelta(days=30)
    assert instancesignup.DAYS_KEPT == 2
    # One until the finer locks are built and measured, from the synthetic
    # run of signup instances at their worst, docs/PRODUCT.md 5g.
    assert instancesignup.LIVE_SIGNUP_INSTANCES == 1
