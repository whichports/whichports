"""An address host never reports by design, so /metrics counts it as its own
state rather than as an agent that failed to start."""
import pytest

from app import db, metrics, store


@pytest.fixture()
def con(tmp_path):
    c = db.connect(str(tmp_path / "m.db"))
    db.init(c)
    yield c
    c.close()


def lines(con):
    return metrics.render(con).splitlines()


def test_an_address_host_is_counted_as_address_not_never_reported(con):
    store.add_address_host(con, "outside-only")
    store.add_host(con, "box")
    out = lines(con)
    assert 'whichports_hosts{state="address"} 1' in out
    assert 'whichports_hosts{state="never_reported"} 1' in out
    assert 'whichports_host_paused{host="outside-only"} 0' in out


def test_a_paused_or_revoked_address_host_keeps_those_words(con):
    store.add_address_host(con, "paused-one")
    store.pause_host(con, "paused-one", True)
    store.add_address_host(con, "gone")
    store.revoke_host(con, "gone")
    out = lines(con)
    assert 'whichports_hosts{state="address"} 0' in out
    assert 'whichports_hosts{state="paused"} 1' in out
    assert 'whichports_hosts{state="revoked"} 1' in out
