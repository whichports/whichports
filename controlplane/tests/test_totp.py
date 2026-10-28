"""The RFC 6238 arithmetic, pinned to the published test vectors.

    python -m pytest tests/test_totp.py

Everything in app/totp.py is a pure function of its arguments, the clock
included, so these tests state exact known values rather than checking that a
number came out. The vectors are the ones printed in the RFCs themselves:

  - RFC 4226 appendix D, the HOTP values for counters 0 to 9.
  - RFC 6238 appendix B, the TOTP values at six given times.

TOTP is HOTP over a time counter, so the first table exercises the truncation
and the second exercises the counter. The RFC prints eight digit codes and this
implementation makes six, which is the same number modulo a smaller power of
ten, so the expected six digits are the last six of the printed eight. That is
a property of the algorithm and not an adjustment: the code is
`number % 10 ** DIGITS`.
"""

import base64

import pytest

from app import totp

# RFC 4226 appendix D and RFC 6238 appendix B both use this ASCII seed. It is
# encoded here rather than written out as base32, so a typo cannot silently
# change what is being tested.
RFC_SEED = base64.b32encode(b"12345678901234567890").decode("ascii")

# RFC 4226 appendix D, "Test Values", the HOTP column for counters 0 to 9.
RFC4226_CODES = ["755224", "287082", "359152", "969429", "338314",
                 "254676", "287922", "162583", "399871", "520489"]

# RFC 6238 appendix B, the SHA1 rows. (unix time, the printed eight digit code)
RFC6238_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


# ------------------------------------------------------------- the vectors

@pytest.mark.parametrize("counter,expected", list(enumerate(RFC4226_CODES)))
def test_the_rfc_4226_hotp_vectors(counter, expected):
    """A TOTP step is an HOTP counter, so appendix D pins the truncation."""
    assert totp.code_at_step(RFC_SEED, counter) == expected


@pytest.mark.parametrize("at_time,printed", RFC6238_VECTORS)
def test_the_rfc_6238_totp_vectors(at_time, printed):
    assert totp.code_at_time(RFC_SEED, at_time) == printed[-totp.DIGITS:]


def test_the_step_boundary_is_where_the_rfc_puts_it():
    """T=59 is inside step 1 and T=60 starts step 2. A test that only checked
    the middle of a step would not notice a floor written as a round."""
    assert totp.time_step(59) == 1
    assert totp.time_step(60) == 2
    assert totp.time_step(0) == 0


# ------------------------------------------------------------- the secret

def test_a_fresh_secret_is_thirty_two_base32_characters_with_no_padding():
    secret = totp.generate_secret()
    assert len(secret) == 32
    assert set(secret) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    assert "=" not in secret


def test_two_secrets_are_not_the_same():
    assert totp.generate_secret() != totp.generate_secret()


def test_the_displayed_grouping_still_decodes():
    """The secret is read off a terminal in groups of four and typed into a
    phone, so the spaces have to survive a round trip."""
    secret = totp.generate_secret()
    grouped = totp.format_secret_groups(secret)
    assert grouped.count(" ") == 7
    assert totp.code_at_time(grouped, 1000) == totp.code_at_time(secret, 1000)


def test_a_lowercased_secret_still_decodes():
    """Some apps and some people lowercase it. Base32 does not care and neither
    should we."""
    secret = totp.generate_secret()
    assert totp.code_at_time(secret.lower(), 1000) == totp.code_at_time(secret, 1000)


# ------------------------------------------------------------ verify_code

def test_the_code_for_now_is_accepted_and_names_its_step():
    at = 1_700_000_000.0
    step = totp.time_step(at)
    assert totp.verify_code(RFC_SEED, totp.code_at_time(RFC_SEED, at), at) == step


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_one_step_either_side_is_accepted(offset):
    """A code typed just before a boundary, or from a phone half a minute out,
    still works."""
    at = 1_700_000_000.0
    code = totp.code_at_step(RFC_SEED, totp.time_step(at) + offset)
    assert totp.verify_code(RFC_SEED, code, at) == totp.time_step(at) + offset


@pytest.mark.parametrize("offset", [-2, 2, -100, 100])
def test_beyond_the_window_is_refused(offset):
    at = 1_700_000_000.0
    code = totp.code_at_step(RFC_SEED, totp.time_step(at) + offset)
    assert totp.verify_code(RFC_SEED, code, at) is None


def test_a_code_from_another_secret_is_refused():
    at = 1_700_000_000.0
    other = totp.generate_secret()
    assert totp.verify_code(RFC_SEED, totp.code_at_time(other, at), at) is None


def test_the_window_can_be_widened_by_the_caller_only_explicitly():
    at = 1_700_000_000.0
    code = totp.code_at_step(RFC_SEED, totp.time_step(at) + 2)
    assert totp.verify_code(RFC_SEED, code, at) is None
    assert totp.verify_code(RFC_SEED, code, at, window=2) is not None


def test_spaces_around_a_submitted_code_are_tolerated():
    at = 1_700_000_000.0
    code = totp.code_at_time(RFC_SEED, at)
    assert totp.verify_code(RFC_SEED, f"  {code[:3]} {code[3:]}  ", at) is not None


@pytest.mark.parametrize("submitted", [
    "", "     ", "12345", "1234567", "abcdef", "12345a", "12 34 5",
    "\n", "000000\x00", "+12345", "-12345", "1.2345",
])
def test_a_malformed_code_is_refused_rather_than_raising(submitted):
    assert totp.verify_code(RFC_SEED, submitted, 1_700_000_000.0) is None


@pytest.mark.parametrize("submitted", [
    "١٢٣٤٥٦",   # Arabic-Indic digits
    "１２３４５６",   # fullwidth digits
    "²²²²²²",   # superscript two
])
def test_non_ascii_digits_are_refused_and_do_not_raise(submitted):
    """`str.isdigit()` says True for all of these, and `hmac.compare_digest`
    raises TypeError on a string holding anything above U+007F. Without the
    ASCII guard this is a 500 on a page a half-signed-in browser can post to,
    not a wrong answer. That is why it has a test of its own."""
    assert len(submitted) == totp.DIGITS
    assert submitted.isdigit()
    assert totp.verify_code(RFC_SEED, submitted, 1_700_000_000.0) is None


def test_a_code_of_all_zeros_is_treated_as_a_code():
    """Left padding means 000000 is a real code some step will produce, so it
    must go through the comparison rather than be screened out as empty."""
    assert totp.verify_code(RFC_SEED, "000000", 1_700_000_000.0) is None


# ---------------------------------------------------------- the otpauth URI

def test_the_uri_carries_what_an_authenticator_app_needs():
    secret = totp.generate_secret()
    uri = totp.otpauth_uri(secret, "sysadmin@example.com")
    # ':' stays literal, which the Key Uri Format allows in as many words, and
    # '@' stays literal, which its own example label, `Example:` followed
    # by a mail address, shows.
    assert uri.startswith("otpauth://totp/whichports:sysadmin@example.com?")
    assert f"secret={secret}" in uri
    assert "issuer=whichports" in uri
    assert "algorithm=SHA1" in uri
    assert f"digits={totp.DIGITS}" in uri
    assert f"period={totp.STEP_SECONDS}" in uri


def test_the_uri_percent_encodes_an_account_that_would_break_it():
    uri = totp.otpauth_uri(totp.generate_secret(), "a b&c=d?e/f")
    assert " " not in uri
    assert "a%20b%26c%3Dd%3Fe%2Ff" in uri
