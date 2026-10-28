"""A certificate has to survive the trip back from a prober on another machine.

`run_to_json` flattens the whole Run with `dataclasses.asdict`, which turns the
Certificate nested inside a TlsResult into a plain dict. `run_from_json` built
the row back with `TlsResult(**row)` and put that dict straight into the field,
so the object came back as a dict wearing a Certificate's name. The next thing
to touch it is `_tls_row`, which reads `certificate.subject`, and the whole
pass for that host died with an AttributeError before a single row was stored.

**Why nothing caught it.** It needs a certificate that was really read and the
wire at the same time. The local path builds the object and never serialises
it, and `test_a_run_survives_the_round_trip` probes with no TLS port, so it
round-tripped an empty certificate list. Even with one it would have passed:
`asdict` of a dict is the same dict, so `run_to_json(run_from_json(x)) == x`
holds while the type is wrong underneath. That is why the assertions here are
about types and about storing, not about equality.

On the remote path, which is the only one the fleet uses, the first port that
answered a handshake would have taken the run down.
"""
import json

import pytest

from app import db, prober

TARGET = "185.199.108.153"

CERTIFICATE = prober.Certificate(
    subject="C=BE,O=Example Org,CN=example.test",
    issuer="C=BE,O=Whichports Test CA,CN=Whichports Test Root",
    not_before="2026-01-01T00:00:00+00:00",
    not_after="2027-01-01T00:00:00+00:00",
    serial="029843a30286345231460da8bd33b7a1",
    self_issued=False,
    names=("example.test", "www.example.test"),
    fingerprint_sha256="ab" * 32)


def a_run(certificate=CERTIFICATE, state=prober.TLS_STATE_READ, reason=None):
    return prober.Run(
        id=None, vantage="probe1",
        started_at="2026-08-27T12:00:00+00:00",
        finished_at="2026-08-27T12:00:01+00:00",
        results=(prober.Result(family="v4", target=TARGET, port=443,
                               state=prober.STATE_CONNECTED,
                               measured_at="2026-08-27T12:00:00+00:00"),),
        certificates=(prober.TlsResult(family="v4", target=TARGET, port=443,
                                       state=state, reason=reason,
                                       certificate=certificate,
                                       read_at="2026-08-27T12:00:01+00:00"),))


def over_the_wire(run):
    """Exactly what dispatch does: JSON out on the vantage host, JSON in here."""
    return prober.run_from_json(json.loads(json.dumps(prober.run_to_json(run))))


@pytest.fixture()
def con(tmp_path):
    c = db.connect(str(tmp_path / "p.db"))
    db.init(c)
    prober.init(c)
    yield c
    c.close()


# ------------------------------------------------------------ the round trip

def test_a_certificate_comes_back_as_a_certificate():
    read = over_the_wire(a_run()).certificates[0].certificate
    assert isinstance(read, prober.Certificate)
    assert read == CERTIFICATE


def test_the_names_come_back_as_a_tuple_and_not_a_list():
    """The field is declared as a tuple and the locally built object holds one.
    A list here would make the same certificate two different values depending
    on which path it arrived by, and Certificate is frozen and compared."""
    read = over_the_wire(a_run()).certificates[0].certificate
    assert isinstance(read.names, tuple)
    assert read.names == ("example.test", "www.example.test")


def test_a_row_that_read_nothing_still_carries_no_certificate():
    read = over_the_wire(a_run(certificate=None,
                               state=prober.TLS_STATE_NOT_READ,
                               reason=prober.REASON_TLS_NO_CERTIFICATE))
    assert read.certificates[0].certificate is None
    assert read.certificates[0].reason == prober.REASON_TLS_NO_CERTIFICATE


def test_the_whole_run_still_round_trips_to_the_same_text():
    once = prober.run_to_json(a_run())
    twice = prober.run_to_json(prober.run_from_json(once))
    assert once == twice


# ------------------------------------------------- and it reaches the database

def test_a_certificate_read_elsewhere_can_be_stored(con):
    """The assertion that would have caught this. `store_measurement` is what
    dispatch calls on whatever came back, and it is where the AttributeError
    was raised."""
    stored = prober.store_measurement(con, None, over_the_wire(a_run()))
    rows = prober.run_certificates(con, stored.id)
    assert len(rows) == 1
    assert rows[0]["subject"] == CERTIFICATE.subject
    assert rows[0]["issuer"] == CERTIFICATE.issuer
    assert rows[0]["fingerprint"] == CERTIFICATE.fingerprint_sha256
    assert rows[0]["names"] == "example.test www.example.test"
    assert rows[0]["self_issued"] == 0


def test_the_stored_row_is_the_same_whichever_path_it_arrived_by(con):
    """A measurement taken here and the same measurement carried back from a
    vantage host have to land as the same row. Two paths that store two
    different things is the shape this project keeps having to correct."""
    here = prober.store_measurement(con, None, a_run())
    there = prober.store_measurement(con, None, over_the_wire(a_run()))
    columns = ("target", "family", "port", "state", "reason", "subject",
               "issuer", "not_before", "not_after", "serial", "self_issued",
               "names", "fingerprint")
    local = prober.run_certificates(con, here.id)[0]
    remote = prober.run_certificates(con, there.id)[0]
    assert [local[c] for c in columns] == [remote[c] for c in columns]


# --------------------------------------------- and a bad one is still refused

@pytest.mark.parametrize("mangle,because", [
    (lambda c: "a string", "a certificate that is not an object"),
    (lambda c: {**c, "surprise": 1}, "a field this build does not know"),
    (lambda c: {k: v for k, v in c.items() if k != "subject"},
     "a field this build needs"),
    (lambda c: {**c, "names": "example.test"}, "names that are not a list"),
    (lambda c: {**c, "names": ["ok", 7]}, "a name that is not text"),
])
def test_a_certificate_this_build_cannot_read_is_refused(mangle, because):
    """The same two rules the rows around it follow. A partial certificate
    stored as though it were read is how a mismatch becomes a stored fact,
    which is `run_from_json`'s own reason for refusing an unknown field."""
    payload = prober.run_to_json(a_run())
    payload["certificates"][0]["certificate"] = mangle(
        payload["certificates"][0]["certificate"])
    with pytest.raises(prober.RunUnreadable):
        prober.run_from_json(payload)
