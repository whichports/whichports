"""The token buckets behind the login form.

    python -m pytest tests/test_ratelimit.py

Tested with an injected clock, so nothing here sleeps. The behaviour that
matters is that a bucket bites, that it hands tokens back, and that a key space
the caller chooses cannot grow this dictionary without limit.
"""

from app import ratelimit


def bucket(capacity=3.0, refill=1.0, max_keys=None):
    clock = [0.0]
    return ratelimit.TokenBucket(capacity, refill, clock=lambda: clock[0],
                                 max_keys=max_keys), clock


def test_a_burst_is_allowed_then_refused():
    b, _ = bucket(capacity=3.0)
    assert [b.allow("k") for _ in range(4)] == [True, True, True, False]


def test_tokens_come_back_over_time():
    b, clock = bucket(capacity=3.0, refill=1.0)
    for _ in range(3):
        b.allow("k")
    assert b.allow("k") is False
    clock[0] += 1.0
    assert b.allow("k") is True
    assert b.allow("k") is False


def test_a_bucket_never_fills_past_its_capacity():
    """An idle hour must not buy an hour's worth of attempts in one second."""
    b, clock = bucket(capacity=3.0, refill=1.0)
    clock[0] += 3600.0
    assert [b.allow("k") for _ in range(4)] == [True, True, True, False]


def test_keys_do_not_share_a_bucket():
    b, _ = bucket(capacity=1.0)
    assert b.allow("one") is True
    assert b.allow("two") is True
    assert b.allow("one") is False


def test_a_clock_that_goes_backwards_does_not_grant_tokens():
    """Boundary: monotonic should never move backwards, and if it somehow does,
    the arithmetic must not credit a negative interval as a refill."""
    b, clock = bucket(capacity=2.0, refill=1.0)
    b.allow("k")
    b.allow("k")
    clock[0] -= 100.0
    assert b.allow("k") is False


def test_the_key_space_is_bounded():
    """The login bucket is keyed by an email the caller chooses, so a spray
    attack would otherwise grow this dictionary until the process dies."""
    b, _ = bucket(capacity=1.0, max_keys=5)
    for i in range(50):
        b.allow(f"key-{i}")
    assert len(b._buckets) == 5


def test_eviction_can_only_ever_weaken_the_limit_for_the_evicted_key():
    """Stated because it is the honest cost of the cap: an evicted key gets a
    fresh bucket when it comes back. It can never lock out a caller who was
    inside the limit."""
    b, _ = bucket(capacity=1.0, max_keys=2)
    assert b.allow("victim") is True
    assert b.allow("victim") is False
    b.allow("second")
    b.allow("third")  # evicts the oldest, which is victim
    assert b.allow("victim") is True


def test_retry_after_is_whole_seconds_and_at_least_one():
    b, _ = bucket(capacity=1.0, refill=1.0 / 30.0)
    assert b.retry_after_seconds("unknown") == 1
    b.allow("k")
    assert b.allow("k") is False
    assert b.retry_after_seconds("k") == 30


def test_retry_after_on_a_bucket_that_never_refills():
    b, _ = bucket(capacity=1.0, refill=0.0)
    b.allow("k")
    assert b.retry_after_seconds("k") == 1


def test_the_login_limiters_are_shaped_for_a_person_not_a_script():
    """A human retrying a typo has to stay comfortable, or the limit becomes
    the thing that locks an operator out of their own fleet."""
    limiters = ratelimit.Limiters()
    assert limiters.login_email.capacity >= 5
    assert limiters.login_email.max_keys == ratelimit.EMAIL_BUCKET_MAX_KEYS
    # The backstop is far above anything a real login rate reaches, so it can
    # only ever catch a spray.
    assert limiters.login_global.capacity >= 10 * limiters.login_email.capacity
    assert limiters.login_global.max_keys is None
