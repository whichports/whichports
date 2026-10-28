"""RFC 6238 TOTP, the six digit codes an authenticator app shows.

Carried over from an earlier project of the author's, reviewed rather than
copied. What came across is the whole of it, because the RFC is small and
the implementation is a pure function of its arguments. What changed
is the issuer name and the house style.

**Stdlib only, and that is not a preference here.** The entire algorithm is
HMAC-SHA1 over a counter plus the dynamic truncation of RFC 4226 section 5.3,
which `hmac`, `struct`, `base64` and `secrets` already cover. A TOTP dependency
would add an attack surface to the process agents post to and buy nothing.

The parameters are the ecosystem defaults, deliberately. Every authenticator
app assumes them when a key is typed in by hand rather than scanned:

  - 20 byte secret, which is RFC 4226's recommended minimum, shown as base32.
  - 30 second step, 6 digits, HMAC-SHA1.
  - Verification accepts one step either side of now, so a code typed just
    before a boundary, or from a phone whose clock is half a minute out, still
    works. Wider would multiply an online guesser's targets for no user gain.

**Replay protection is not here.** It needs state, the last accepted step, and
that lives with the user row in `app/accounts.py`. Everything in this file
takes its clock as an argument, so the tests pin exact RFC vectors instead of
waiting for a real clock to move.
"""

import base64
import hmac
import secrets
import struct
from urllib.parse import quote

SECRET_BYTES = 20
STEP_SECONDS = 30
DIGITS = 6
VERIFY_WINDOW_STEPS = 1

# Shown by the authenticator app beside the account email.
ISSUER = "whichports"


def generate_secret() -> str:
    """A fresh 160 bit secret as base32. Twenty bytes encode to exactly 32
    characters, so there is no '=' padding to confuse anyone typing it in."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii")


def format_secret_groups(secret: str) -> str:
    """The secret in groups of four, which is how it gets read off a terminal
    and typed into a phone. Decoding strips the spaces again."""
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


def _decode_secret(secret: str) -> bytes:
    """Base32 decode, tolerating the display formatting: spaces, lowercase,
    and the missing '=' padding."""
    normalized = secret.replace(" ", "").upper()
    return base64.b32decode(normalized + "=" * (-len(normalized) % 8))


def time_step(at_time: float) -> int:
    """The counter for a unix time: whole steps since the epoch."""
    return int(at_time // STEP_SECONDS)


def code_at_step(secret: str, step: int) -> str:
    """The code for one counter value: HMAC-SHA1 over the big endian 64 bit
    counter, dynamically truncated per RFC 4226 section 5.3, modulo ten to the
    sixth, left padded with zeros."""
    digest = hmac.new(_decode_secret(secret), struct.pack(">Q", step), "sha1").digest()
    offset = digest[-1] & 0x0F
    (number,) = struct.unpack(">I", digest[offset:offset + 4])
    number &= 0x7FFFFFFF
    return str(number % 10 ** DIGITS).zfill(DIGITS)


def code_at_time(secret: str, at_time: float) -> str:
    """The code an authenticator app shows at a given unix time."""
    return code_at_step(secret, time_step(at_time))


def verify_code(secret: str, code: str, at_time: float,
                window: int = VERIFY_WINDOW_STEPS) -> int | None:
    """Check a submitted code against the steps within the window either side
    of now.

    Returns the step that matched, which is what the caller's replay guard
    needs, or None. Every candidate is compared with `hmac.compare_digest` and
    none is skipped after a match, so the work done does not depend on which
    candidate matched or on whether any did.
    """
    submitted = code.strip().replace(" ", "")
    if len(submitted) != DIGITS or not _is_ascii_digits(submitted):
        return None
    current = time_step(at_time)
    matched: int | None = None
    for candidate in range(max(0, current - window), current + window + 1):
        if hmac.compare_digest(code_at_step(secret, candidate), submitted) and matched is None:
            matched = candidate
    return matched


def _is_ascii_digits(value: str) -> bool:
    """Whether every character is one of 0 to 9.

    **`str.isdigit()` alone is not that check**, and the difference is a crash
    rather than a wrong answer. It answers True for the Arabic-Indic digits and
    for superscripts, and `hmac.compare_digest` raises TypeError the moment
    either side holds a codepoint above U+007F. Unguarded, a code field
    containing six non-ASCII digits turns a refusal into a 500 on a page a
    half-signed-in browser can reach. `app/web_auth.py` guards its CSRF
    comparison for exactly this reason, and the note there is worth reading.
    """
    return value.isascii() and value.isdigit()


def otpauth_uri(secret: str, account: str) -> str:
    """The otpauth:// URI an authenticator app accepts as typed or pasted
    input, and as the payload behind a QR code if one is ever drawn.

    The shape is the Key Uri Format, read from
    github.com/google/google-authenticator/wiki/Key-Uri-Format on 2026-08-22.
    Two things it says that this function relies on. The issuer prefix and the
    account name are separated by "a literal or url-encoded colon", so leaving
    the colon literal is correct, and its own example writes an email address
    straight into the label. And carrying the issuer in both places is
    "STRONGLY RECOMMENDED": when both are present they should be equal, and
    newer readers use the parameter "for internal disambiguation".

    The other three parameters are written out rather than left to default,
    even though SHA1, 6 and 30 are the documented defaults, because a URI that
    states them cannot be misread by an app that defaults differently.
    """
    label = quote(f"{ISSUER}:{account}", safe=":@")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={ISSUER}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}")
