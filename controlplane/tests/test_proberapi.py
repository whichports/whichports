"""The prober API's queue, checks and pace (`app/proberapi.py`).

No HTTP and no prober here. `tests/test_proberapi_routes.py` drives the same
rules through the ingest, and `tests/test_proberapi_worker.py` drives the
prober. What these hold:

  - a batch is exactly what `dispatch.build_batch` makes, and every other
    shape is refused with one class from the closed set
  - the instance's own snapshot is read for its targets only
  - one batch in flight per instance, and a budget of connects an hour, both
    per instance and never shared
  - an instance cannot see another instance's batch, and cannot tell it from
    one that never existed
  - what is kept, and that it goes when its time is up
"""
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app import authz, db, dispatch, instances, proberapi, vantages

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"
OTHER_V4 = "185.199.108.154"
PROBE1_V4 = "78.141.210.130"
PROBE2_V4 = "185.199.110.7"
ENABLED = {"probe1", "probe2"}
OURS = frozenset({PROBE1_V4, PROBE2_V4})


@pytest.fixture()
def con():
    connection = db.connect(":memory:")
    for module in (db, authz, vantages, instances, proberapi):
        module.init(connection)
    yield connection
    connection.close()


def snapshot(targets, now=NOW):
    """An instance's own snapshot, in the wire form its dispatch sends."""
    return authz.snapshot_to_json(authz.SnapshotAuthority(
        {t: now + timedelta(days=1) for t in targets},
        now + timedelta(minutes=15)))


def batch(**overrides):
    base = {"version": dispatch.BATCH_VERSION, "vantage": "probe1",
            "addresses": [V4], "ports": [22, 80, 443], "tls_ports": [443],
            "snapshot": snapshot([V4])}
    base.update(overrides)
    return base


def parse(payload):
    return proberapi.parse_batch(payload, ENABLED, OURS)


def refused_with(payload):
    with pytest.raises(proberapi.Refused) as caught:
        parse(payload)
    return caught.value.error


# ================================================================ the shape

def test_the_batch_dispatch_builds_is_accepted_as_it_is(con):
    """The instance runs the same dispatch we do, so its batch is ours byte
    for byte. Built here by the real function against a registry where the
    address is proved."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    authz.verify_proof(con, challenge.id, now=NOW,
                       resolver=lambda name: [challenge.token])
    built = dispatch.build_batch(con, "probe1", [V4, V6], [22, 80], tls_ports=[443],
                                 now=NOW)
    parsed = parse(json.loads(json.dumps(built)))
    assert parsed.vantage == "probe1"
    assert parsed.addresses == (V4, V6)
    assert parsed.ports == (22, 80)
    assert parsed.tls_ports == (443,)
    # Only what the instance's own registry allowed, canonical.
    assert parsed.allowed == (V4,)


def test_their_snapshot_is_read_for_its_targets_and_nothing_else():
    wide = {"version": 1, "expires_at": "2000-01-01T00:00:00+00:00",
            "targets": {V4: "2000-01-01T00:00:00+00:00",
                        "2606:50C0:8000:0::153": "2000-01-01T00:00:00+00:00"}}
    # Long expired by our clock, and still read: the times are theirs, and
    # only which addresses they allowed is used (`app/proberapi.py`).
    parsed = parse(batch(snapshot=wide))
    assert parsed.allowed == tuple(sorted([V4, V6]))


@pytest.mark.parametrize("payload, error", [
    ([], "malformed_request"),
    ("batch", "malformed_request"),
    (None, "malformed_request"),
    (batch(version=2), "unsupported_version"),
    ({k: v for k, v in batch().items() if k != "version"}, "unsupported_version"),
    (batch(version="1"), "unsupported_version"),
    (batch(vantage=None), "malformed_request"),
    (batch(vantage=1), "malformed_request"),
    (batch(vantage="probe3"), "unknown_vantage"),
    (batch(vantage=" probe1"), "unknown_vantage"),
    (batch(addresses=[]), "malformed_request"),
    (batch(addresses=V4), "malformed_request"),
    (batch(addresses=[V4] * 17), "malformed_request"),
    (batch(addresses=[4]), "malformed_request"),
    (batch(addresses=["1" * 65]), "malformed_request"),
    (batch(addresses=[V4, PROBE1_V4]), "names_a_vantage_address"),
    (batch(addresses=["78.141.210.130"]), "names_a_vantage_address"),
    (batch(ports=None), "malformed_request"),
    (batch(ports=list(range(1, 202))), "malformed_request"),
    (batch(ports=[22.0]), "malformed_request"),
    (batch(ports=[True]), "malformed_request"),
    (batch(ports=[[22]]), "malformed_request"),
    (batch(ports=["x" * 17]), "malformed_request"),
    (batch(tls_ports=None), "malformed_request"),
    (batch(tls_ports=[0]), "malformed_request"),
    (batch(tls_ports=[65536]), "malformed_request"),
    (batch(tls_ports=["443"]), "malformed_request"),
    (batch(tls_ports=[False]), "malformed_request"),
    (batch(tls_ports=list(range(1, 66))), "malformed_request"),
    ({k: v for k, v in batch().items() if k != "snapshot"}, "malformed_request"),
    (batch(snapshot={"version": 1}), "malformed_request"),
    (batch(snapshot={"version": 1, "expires_at": "x", "targets": {}}),
     "malformed_request"),
    (batch(snapshot={"version": 1, "expires_at": NOW.isoformat(),
                     "targets": {"10.0.0.1": NOW.isoformat()}}),
     "malformed_request"),
])
def test_every_other_shape_is_refused_with_its_class(payload, error):
    assert refused_with(payload) == error


def test_a_disabled_vantage_cannot_be_asked_for_and_its_address_stays_ours():
    with pytest.raises(proberapi.Refused) as caught:
        proberapi.parse_batch(batch(vantage="probe2"), {"probe1"}, OURS)
    assert caught.value.error == "unknown_vantage"
    with pytest.raises(proberapi.Refused) as caught:
        proberapi.parse_batch(batch(addresses=[PROBE2_V4]), {"probe1"}, OURS)
    assert caught.value.error == "names_a_vantage_address"


def test_a_port_or_an_address_that_is_not_one_still_travels():
    """The engine records both as not tested with its own reason, the same as
    an ssh pass does, so the API does not second guess it."""
    parsed = parse(batch(addresses=[V4, "not-an-address"], ports=[22, "ssh"]))
    assert parsed.addresses == (V4, "not-an-address")
    assert parsed.ports == (22, "ssh")


def test_an_empty_port_list_is_a_real_batch():
    """A host with nothing listening is an answer (dispatch.batches)."""
    assert parse(batch(ports=[], tls_ports=[])).ports == ()


def test_every_error_class_is_in_the_closed_set_with_a_status():
    assert all(isinstance(status, int) for status in proberapi.ERRORS.values())
    assert proberapi.ERRORS["unknown_key"] == 401
    assert proberapi.ERRORS["over_instance_pace"] == 429
    with pytest.raises(ValueError):
        proberapi.Refused("something went wrong on our side")


def test_the_charge_is_the_most_a_batch_can_cost():
    parsed = parse(batch(addresses=[V4, V6], ports=[22, 80, 443, "x"],
                         tls_ports=[443, 8443]))
    # four ports each, and one certificate read, on 443, which is probed.
    assert parsed.per_address() == 5
    assert parsed.charge() == 10


def test_a_request_survives_the_queue_unchanged():
    parsed = parse(batch(addresses=[V4, V6], ports=[22, "x"]))
    assert proberapi.BatchRequest.from_json(parsed.to_json()) == parsed


# ================================================================ the queue

def add(con, name):
    return instances.add(con, name, now=NOW, origin=authz.ORIGIN_INVITED).instance


def test_submit_queues_and_fetch_says_queued(con):
    one = add(con, "one")
    batch_id = proberapi.submit(con, one.id, parse(batch()), NOW)
    assert proberapi.fetch(con, one.id, batch_id, NOW) == {"state": "queued"}


def test_one_batch_in_flight_per_instance_and_never_shared(con):
    one, two = add(con, "one"), add(con, "two")
    proberapi.submit(con, one.id, parse(batch()), NOW)
    with pytest.raises(proberapi.Refused) as caught:
        proberapi.submit(con, one.id, parse(batch()), NOW)
    assert caught.value.error == "batch_in_flight"
    assert caught.value.status == 409
    # The other instance's slot is its own.
    proberapi.submit(con, two.id, parse(batch()), NOW)


def test_a_finished_batch_frees_the_slot_before_it_is_collected(con):
    one = add(con, "one")
    first = proberapi.submit(con, one.id, parse(batch()), NOW)
    row = proberapi.next_queued(con, NOW)
    assert proberapi.mark_started(con, first, NOW)
    proberapi.record_failure(con, row, "vantage_unreachable", NOW)
    proberapi.submit(con, one.id, parse(batch()), NOW)


def test_fetch_hands_over_the_answer_once_and_forgets_it(con):
    one = add(con, "one")
    batch_id = proberapi.submit(con, one.id, parse(batch()), NOW)
    row = proberapi.next_queued(con, NOW)
    proberapi.mark_started(con, batch_id, NOW)
    assert proberapi.fetch(con, one.id, batch_id, NOW) == {"state": "running"}
    proberapi.record_answer(con, row, '{"vantage": "probe1"}', NOW)
    assert proberapi.fetch(con, one.id, batch_id, NOW) == {
        "state": "done", "answer": {"vantage": "probe1"}}
    with pytest.raises(proberapi.Refused) as caught:
        proberapi.fetch(con, one.id, batch_id, NOW)
    assert caught.value.error == "unknown_batch"
    assert con.execute("SELECT COUNT(*) FROM prober_api_batches").fetchone()[0] == 0


def test_a_failure_is_handed_over_as_its_class(con):
    one = add(con, "one")
    batch_id = proberapi.submit(con, one.id, parse(batch()), NOW)
    row = proberapi.next_queued(con, NOW)
    proberapi.mark_started(con, batch_id, NOW)
    proberapi.record_failure(con, row, "prober_refused", NOW)
    assert proberapi.fetch(con, one.id, batch_id, NOW) == {
        "state": "failed", "error": "prober_refused"}
    with pytest.raises(ValueError):
        proberapi.record_failure(con, row, "it broke", NOW)


def test_another_instances_batch_reads_as_one_that_never_existed(con):
    one, two = add(con, "one"), add(con, "two")
    batch_id = proberapi.submit(con, one.id, parse(batch()), NOW)
    for asked in (batch_id, "nope", "", None, 7, "x" * 65):
        with pytest.raises(proberapi.Refused) as caught:
            proberapi.fetch(con, two.id, asked, NOW)
        assert caught.value.error == "unknown_batch"
    # And asking did not take it away from its owner.
    assert proberapi.fetch(con, one.id, batch_id, NOW)["state"] == "queued"


def test_a_batch_id_is_not_a_number_to_walk(con):
    one = add(con, "one")
    ids = set()
    for n in range(5):
        batch_id = proberapi.submit(con, one.id, parse(batch()),
                                    NOW + timedelta(seconds=n))
        row = proberapi.next_queued(con, NOW + timedelta(seconds=n))
        proberapi.mark_started(con, batch_id, NOW)
        proberapi.record_failure(con, row, "prober_refused", NOW)
        ids.add(batch_id)
    assert len(ids) == 5
    assert all(len(i) >= 32 and not i.isdigit() for i in ids)


def test_mark_started_claims_a_batch_once(con):
    one = add(con, "one")
    batch_id = proberapi.submit(con, one.id, parse(batch()), NOW)
    assert proberapi.mark_started(con, batch_id, NOW)
    assert not proberapi.mark_started(con, batch_id, NOW)
    assert not proberapi.mark_started(con, "gone", NOW)
    assert proberapi.next_queued(con, NOW) is None


def test_the_queue_is_served_oldest_first_across_instances(con):
    one, two = add(con, "one"), add(con, "two")
    later = proberapi.submit(con, two.id, parse(batch()), NOW + timedelta(seconds=5))
    earlier = proberapi.submit(con, one.id, parse(batch()), NOW)
    assert proberapi.next_queued(con, NOW + timedelta(seconds=6))["id"] == earlier
    proberapi.mark_started(con, earlier, NOW)
    assert proberapi.next_queued(con, NOW + timedelta(seconds=6))["id"] == later


def test_submit_from_two_threads_at_once_queues_exactly_one(tmp_path):
    """The in-flight check and the insert are one write transaction, so two
    requests from one instance landing together cannot both get in."""
    path = str(tmp_path / "cp.db")
    setup = db.connect(path)
    for module in (db, authz, vantages, instances, proberapi):
        module.init(setup)
    one = instances.add(setup, "one", now=NOW, origin=authz.ORIGIN_INVITED).instance
    setup.close()

    results, gate = [], threading.Barrier(8)

    def attempt():
        con = db.connect(path)
        try:
            gate.wait()
            proberapi.submit(con, one.id, parse(batch()), NOW)
            results.append("queued")
        except proberapi.Refused as refused:
            results.append(refused.error)
        finally:
            con.close()

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == ["batch_in_flight"] * 7 + ["queued"]


# ================================================================= the pace

def _queue_and_finish(con, instance, payload, at):
    batch_id = proberapi.submit(con, instance.id, parse(payload), at)
    row = proberapi.next_queued(con, at)
    assert row["id"] == batch_id
    proberapi.mark_started(con, batch_id, at)
    proberapi.record_failure(con, row, "prober_refused", at)


def spend(con, instance, connects, at):
    """Charge exactly `connects` at `at`, the way an instance really spends:
    batches of the largest size the checks allow, then single-address
    batches for what is left."""
    largest = batch(addresses=[V4] * proberapi.MAX_ADDRESSES,
                    ports=list(range(1, proberapi.MAX_PORTS + 1)), tls_ports=[])
    size = parse(largest).charge()
    while connects >= size:
        _queue_and_finish(con, instance, largest, at)
        connects -= size
    while connects > 0:
        ports = min(connects, proberapi.MAX_PORTS)
        _queue_and_finish(con, instance, batch(ports=list(range(1, ports + 1)),
                                               tls_ports=[]), at)
        connects -= ports


def charged(con, instance):
    return con.execute("SELECT SUM(connects) FROM prober_api_charges"
                       " WHERE instance_id = ?", (instance.id,)).fetchone()[0]


def test_an_instance_cannot_spend_more_than_its_hour(con):
    one = add(con, "one")
    spend(con, one, proberapi.CONNECTS_PER_HOUR, NOW)
    assert charged(con, one) == proberapi.CONNECTS_PER_HOUR
    # One connect more is one too many.
    with pytest.raises(proberapi.Refused) as caught:
        proberapi.submit(con, one.id, parse(batch(ports=[22], tls_ports=[])),
                         NOW + timedelta(minutes=30))
    assert caught.value.error == "over_instance_pace"
    assert caught.value.status == 429
    # Room comes back when the charges are an hour old, thirty minutes from
    # the refusal, and the answer says so.
    assert 30 * 60 <= caught.value.retry_after <= 30 * 60 + 1


def test_exactly_the_budget_fits(con):
    one = add(con, "one")
    spend(con, one, proberapi.CONNECTS_PER_HOUR - 1, NOW)
    proberapi.submit(con, one.id, parse(batch(ports=[22], tls_ports=[])), NOW)


def test_the_hour_slides_and_old_charges_stop_counting(con):
    one = add(con, "one")
    spend(con, one, proberapi.CONNECTS_PER_HOUR, NOW)
    after = NOW + timedelta(hours=1, seconds=1)
    proberapi.submit(con, one.id, parse(batch()), after)


def test_one_instance_spending_its_hour_leaves_the_other_untouched(con):
    one, two = add(con, "one"), add(con, "two")
    spend(con, one, proberapi.CONNECTS_PER_HOUR, NOW)
    proberapi.submit(con, two.id, parse(batch()), NOW + timedelta(seconds=1))


def test_a_refused_batch_is_not_charged(con):
    one = add(con, "one")
    proberapi.submit(con, one.id, parse(batch()), NOW)
    with pytest.raises(proberapi.Refused):
        proberapi.submit(con, one.id, parse(batch()), NOW)
    assert con.execute("SELECT COUNT(*) FROM prober_api_charges").fetchone()[0] == 1


def test_the_budget_is_the_number_that_was_accepted():
    """30,000 an hour, accepted 2026-09-30. A change is the owner's."""
    assert proberapi.CONNECTS_PER_HOUR == 30_000
    assert proberapi.PACE_WINDOW_SECONDS == 3600


# ============================================================ what is kept

def test_a_batch_is_gone_fifteen_minutes_after_it_was_queued(con):
    one = add(con, "one")
    batch_id = proberapi.submit(con, one.id, parse(batch()), NOW)
    later = NOW + timedelta(seconds=proberapi.BATCH_TTL_SECONDS + 1)
    assert proberapi.next_queued(con, later) is None
    with pytest.raises(proberapi.Refused):
        proberapi.fetch(con, one.id, batch_id, later)
    # And its slot is free.
    proberapi.submit(con, one.id, parse(batch()), later)


def test_a_finished_answer_is_gone_by_the_same_rule(con):
    one = add(con, "one")
    batch_id = proberapi.submit(con, one.id, parse(batch()), NOW)
    row = proberapi.next_queued(con, NOW)
    proberapi.mark_started(con, batch_id, NOW)
    proberapi.record_answer(con, row, "{}", NOW)
    proberapi.sweep(con, NOW + timedelta(seconds=proberapi.BATCH_TTL_SECONDS + 1))
    assert con.execute("SELECT COUNT(*) FROM prober_api_batches").fetchone()[0] == 0


def test_charges_go_after_the_hour_and_the_log_after_thirty_days(con):
    one = add(con, "one")
    proberapi.submit(con, one.id, parse(batch()), NOW)
    proberapi.log_sent(con, one.id, "probe1", [V4], 4, NOW)
    proberapi.sweep(con, NOW + timedelta(hours=1, seconds=1))
    assert con.execute("SELECT COUNT(*) FROM prober_api_charges").fetchone()[0] == 0
    assert len(proberapi.log_for_target(con, V4)) == 1
    proberapi.sweep(con, NOW + timedelta(days=30, seconds=1))
    assert proberapi.log_for_target(con, V4) == []


def test_the_retention_is_the_number_that_was_accepted():
    assert proberapi.LOG_RETENTION_SECONDS == 30 * 24 * 60 * 60
    assert proberapi.BATCH_TTL_SECONDS == 15 * 60


def test_the_abuse_log_is_one_row_per_instance_vantage_address_and_day(con):
    one, two = add(con, "one"), add(con, "two")
    for minute in range(3):
        proberapi.log_sent(con, one.id, "probe1", [V4, V6], 5,
                           NOW + timedelta(minutes=minute))
    proberapi.log_sent(con, one.id, "probe2", [V4], 5, NOW)
    proberapi.log_sent(con, two.id, "probe1", [V4], 5, NOW)
    proberapi.log_sent(con, one.id, "probe1", [V4], 5, NOW + timedelta(days=1))

    rows = proberapi.log_for_target(con, V4)
    summary = sorted((r["instance_name"], r["vantage"], r["day"], r["batches"],
                      r["connects"]) for r in rows)
    assert summary == [
        ("one", "probe1", "2026-09-30", 3, 15),
        ("one", "probe1", "2026-10-01", 1, 5),
        ("one", "probe2", "2026-09-30", 1, 5),
        ("two", "probe1", "2026-09-30", 1, 5),
    ]
    first = [r for r in rows if r["instance_name"] == "one"
             and r["vantage"] == "probe1" and r["day"] == "2026-09-30"][0]
    assert first["first_at"] < first["last_at"]


def test_the_abuse_log_holds_no_port_and_no_result(con):
    columns = {row[1] for row in con.execute("PRAGMA table_info(prober_api_log)")}
    assert columns == {"instance_id", "vantage", "target", "day", "first_at",
                       "last_at", "batches", "connects"}


def test_the_log_finds_an_address_however_it_is_spelled(con):
    one = add(con, "one")
    proberapi.log_sent(con, one.id, "probe1", [V6], 1, NOW)
    assert len(proberapi.log_for_target(con, "2606:50C0:8000:0000::153")) == 1


def test_every_stamp_is_one_fixed_width(con):
    """The sweep and the pace compare stamps as text."""
    plain = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
    fine = plain.replace(microsecond=1)
    naive = datetime(2026, 9, 30, 12, 0)
    assert len({len(proberapi.stamp(t)) for t in (plain, fine, naive)}) == 1
    assert proberapi.stamp(plain) < proberapi.stamp(fine)
    assert proberapi.stamp(naive) == proberapi.stamp(plain)


def test_init_is_idempotent(con):
    proberapi.init(con)
    proberapi.init(con)
    assert isinstance(con, sqlite3.Connection)
