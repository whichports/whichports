"""Token buckets, so a login form is not an unlimited guessing machine.

Carried over from an earlier project of the author's, reviewed rather than
copied, and cut down to the two buckets a login needs. More buckets arrive
with the endpoints that need them, not before.

  - **Per email.** The tight bound. A human retrying a typo stays comfortable
    and an online guesser gets about two attempts a minute, which is nothing
    against a twelve character minimum.
  - **A global backstop.** Spraying one attempt across a thousand addresses
    walks straight past a per-email bucket, so a second bucket bounds the whole
    endpoint. Sized so it could never bite a real operator: nobody signs in a
    hundred times in a minute.
  - **Per account, for the second factor**, plus a global backstop of its own.
    Six digits is a million guesses, so this is the bucket that has to be
    tight.

    **It is keyed on the account and not on the pending session, and that is
    the whole design.** Somebody at the code page already knows the password,
    so they can mint as many pending sessions as they like. A per-session
    bucket would hand each one a full allowance and bound nothing. The account
    is the thing there is only one of.

    There is deliberately no per-IP bucket. Trusting a forwarded address is its
    own careful piece of work (`ingest.observed_source_address`), and an
    attacker who can spread over addresses cannot spread over the one account
    they are attacking.

Honest limits of this design, stated rather than discovered later:

  - **The state is in this process's memory.** If the ingest is ever run with
    more than one worker, the effective limit multiplies by the worker count.
    These are guardrails against a script in a loop, not precision metering.
  - **A restart forgets every bucket.** Acceptable: they refill in a minute
    anyway, and the thing that actually protects a password is its length and
    the cost of the hash behind it.
  - **The email is chosen by the caller**, so the key space is theirs to grow.
    That is what `max_keys` bounds, and eviction can only ever hand back a
    fresh bucket to a key that had already spent tokens. It can never lock out
    somebody who was inside the limit.
"""

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

# Per email: ten in a burst, then one every thirty seconds.
LOGIN_EMAIL_CAPACITY = 10.0
LOGIN_EMAIL_REFILL_PER_SECOND = 1.0 / 30.0

# The backstop across every address at once. A whole office signing in at nine
# in the morning is nowhere near this; a spray attack is.
LOGIN_GLOBAL_CAPACITY = 100.0
LOGIN_GLOBAL_REFILL_PER_SECOND = 1.0

# The second factor, per account. Five wrong codes in a burst, then one every
# thirty seconds. Against six digits that is under three guesses a minute at a
# million to one each, and the pending session expires in ten minutes anyway
# (accounts.PENDING_SESSION_TTL). An operator who mistypes a code twice never
# notices this.
TOTP_USER_CAPACITY = 5.0
TOTP_USER_REFILL_PER_SECOND = 1.0 / 30.0

# The backstop across every account at once, for the same reason the login has
# one. Sized so a real operator retyping a code never meets it.
TOTP_GLOBAL_CAPACITY = 50.0
TOTP_GLOBAL_REFILL_PER_SECOND = 1.0

# The beta signup, per client: five in a burst, then one a minute. Somebody
# who mistypes their address twice never meets it.
#
# **This is the one bucket keyed on an address, and it is the weak one of the
# pair.** The address comes from a header a proxy set (`app/betasignup_routes.py`
# says which). It is the client's own only where the proxy in front removes a
# copy the client typed. Where it does not, anybody can type the header and
# get a fresh bucket each time. So it stops a script in a loop from one place
# and nothing more, and the global bucket below is the bound.
BETA_CLIENT_CAPACITY = 5.0
BETA_CLIENT_REFILL_PER_SECOND = 1.0 / 60.0

# The backstop across every client at once: three hundred in a burst, then
# one a second. A row is an address, a word and a time, so an hour of this
# flat out is 3,600 small rows, and a real launch day is nowhere near it.
BETA_GLOBAL_CAPACITY = 300.0
BETA_GLOBAL_REFILL_PER_SECOND = 1.0

# The mail that tells the operator somebody joined: twenty in a burst, then
# one every three minutes. A join past that is stored like any other and
# simply sends no mail, and the next mail's count includes it.
BETA_MAIL_CAPACITY = 20.0
BETA_MAIL_REFILL_PER_SECOND = 1.0 / 180.0

# Roughly a megabyte of entries. The cap bounds memory, it is not meant to be
# reached by anything legitimate.
EMAIL_BUCKET_MAX_KEYS = 10_000

# The one key the global bucket counts under.
GLOBAL_KEY = "global"


@dataclass
class _BucketState:
    tokens: float
    last_refill: float


class TokenBucket:
    """One bucket per key: `capacity` in a burst, `refill_per_second`
    sustained. Locked, because FastAPI runs synchronous handlers in a thread
    pool and two of them can arrive at once. The clock is injectable so tests
    can move time without sleeping through it."""

    def __init__(self, capacity: float, refill_per_second: float,
                 clock: Callable[[], float] = time.monotonic,
                 max_keys: int | None = None) -> None:
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self.max_keys = max_keys
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[str, _BucketState] = {}

    def allow(self, key: str) -> bool:
        """Take one token for this key. False means the bucket is empty."""
        now = self._clock()
        with self._lock:
            state = self._buckets.get(key)
            if state is None:
                if self.max_keys is not None and len(self._buckets) >= self.max_keys:
                    # Oldest inserted goes. Crude on purpose: the evicted key
                    # gets a full bucket if it comes back, so eviction can only
                    # weaken the limit for a key that had already spent
                    # tokens, never tighten it for anyone else.
                    self._buckets.pop(next(iter(self._buckets)))
                state = _BucketState(tokens=self.capacity, last_refill=now)
                self._buckets[key] = state
            else:
                elapsed = max(0.0, now - state.last_refill)
                state.tokens = min(self.capacity,
                                   state.tokens + elapsed * self.refill_per_second)
                state.last_refill = now
            if state.tokens >= 1.0:
                state.tokens -= 1.0
                return True
            return False

    def retry_after_seconds(self, key: str) -> int:
        """Whole seconds until one token is back, at least one, for the
        Retry-After header. Called after a refusal; an unknown key means one."""
        with self._lock:
            state = self._buckets.get(key)
            if state is None or self.refill_per_second <= 0:
                return 1
            deficit = 1.0 - state.tokens
            if deficit <= 0:
                return 1
            return max(1, int(deficit / self.refill_per_second + 0.999))


@dataclass
class Limiters:
    """The set the application holds. A plain object rather than module
    globals, so a test builds an isolated one and the app owns exactly one."""

    login_email: TokenBucket = field(default_factory=lambda: TokenBucket(
        LOGIN_EMAIL_CAPACITY, LOGIN_EMAIL_REFILL_PER_SECOND,
        max_keys=EMAIL_BUCKET_MAX_KEYS))
    login_global: TokenBucket = field(default_factory=lambda: TokenBucket(
        LOGIN_GLOBAL_CAPACITY, LOGIN_GLOBAL_REFILL_PER_SECOND))
    totp_user: TokenBucket = field(default_factory=lambda: TokenBucket(
        TOTP_USER_CAPACITY, TOTP_USER_REFILL_PER_SECOND,
        max_keys=EMAIL_BUCKET_MAX_KEYS))
    totp_global: TokenBucket = field(default_factory=lambda: TokenBucket(
        TOTP_GLOBAL_CAPACITY, TOTP_GLOBAL_REFILL_PER_SECOND))
    beta_client: TokenBucket = field(default_factory=lambda: TokenBucket(
        BETA_CLIENT_CAPACITY, BETA_CLIENT_REFILL_PER_SECOND,
        max_keys=EMAIL_BUCKET_MAX_KEYS))
    beta_global: TokenBucket = field(default_factory=lambda: TokenBucket(
        BETA_GLOBAL_CAPACITY, BETA_GLOBAL_REFILL_PER_SECOND))
    beta_mail: TokenBucket = field(default_factory=lambda: TokenBucket(
        BETA_MAIL_CAPACITY, BETA_MAIL_REFILL_PER_SECOND))
