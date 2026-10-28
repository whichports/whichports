"""The QR code on the authenticator-app window, as data rather than as markup.

Carried over from an earlier project of the author's, which shipped the same
screen, reviewed rather than pasted. That project rendered the SVG here and
dropped it into a server-side template.
This product's enrolment is a window in the dashboard, so what crosses the
wire is the matrix and the window draws it: **nothing in the browser parses
markup out of an answer, and the page still contains no image and fetches
nothing** (`tests/test_render_live.py` holds both rules for the whole page).

**Kept apart from `app/totp.py` on purpose.** That module is the RFC 6238
arithmetic and the secret, stdlib only. Turning a string into squares is a
display concern and has no business sitting beside secret generation.

**Why a library rather than our own encoder.** A QR encoder is Reed-Solomon
over GF(256), masking and format bits, and a code we wrote that scans on four
phones out of five is worse than no picture at all, which is exactly what the
window falls back to. `segno` is pure Python, has no dependencies of its own,
is BSD licensed, and does the one thing. The justification is in
`pyproject.toml` beside the pin.

**The import is lazy and a failure is not fatal.** A box where `uv sync` has
not run yet must lose the picture and keep the key, rather than lose the
ability to turn two-factor on.
"""

# Medium recovery, the usual level for an enrolment QR: it survives screen
# glare and a phone held at an angle, and the extra modules cost nothing at
# this size.
ERROR_LEVEL = "m"

# The standard four-module quiet zone, without which scanners do not lock on.
# It is added here rather than left to the window, so every drawing of this
# matrix has it whatever draws it.
QUIET_ZONE = 4


def qr_matrix(uri: str) -> list:
    """The QR as rows of "0" and "1", quiet zone included, or an empty list.

    One string per row, because that is the smallest thing to send and the
    easiest to walk: the window turns runs of "1" into one path and draws it
    with `createElementNS`, so no markup crosses the wire in either direction.

    Empty rather than an exception. The caller draws the key either way, and
    the key alone is a working enrolment.
    """
    if not uri:
        return []
    try:
        import segno
    except ImportError:
        return []
    try:
        rows = ["".join("1" if bit else "0" for bit in row)
                for row in segno.make(uri, error=ERROR_LEVEL).matrix]
    except Exception:
        # A picture that will not draw is a picture the window does without.
        # It is never a reason an operator cannot turn two-factor on.
        return []
    if not rows:
        return []
    width = len(rows[0]) + QUIET_ZONE * 2
    blank = "0" * width
    quiet = [blank] * QUIET_ZONE
    padded = ["0" * QUIET_ZONE + row + "0" * QUIET_ZONE for row in rows]
    return quiet + padded + quiet
