"""Whether anybody may create an account, and who.

The owner, 2026-08-23: the login page says that no new account can be made, none
is accepted, and he names the addresses that may register while he tests.

So this is a gate rather than a notice. **A banner that only says no is a lie
the moment somebody posts the form anyway**, and both ways in have to ask the
same question: the register form and a provider sign-in that would otherwise
create an account for an identity nobody has seen.

**Closed is the default**, deliberately. This gate exists because the product is
not open yet, and a configuration mistake should leave it shut rather than open.
An operator with a shell can always make an account with `users_cli add`, which
is how the first one is made and how it worked before any of this existed.

Two variables, both read from `/etc/whichports/controlplane.env`:

  - `WHICHPORTS_SIGNUP` is `closed` or `open`. Anything else, including a typo,
    reads as closed for the reason above.
  - `WHICHPORTS_SIGNUP_ALLOW` is addresses that may sign up whatever the mode
    says, separated by commas or whitespace. This is the "tell me the emails I
    want to add" half: one line in a file, no deploy, no code change.

The allow list is checked against the address the provider reports, or the one
typed into the register form. **That is not an authorisation decision about an
existing account**, which is the thing `app/identities.py` refuses to do with an
address. It only decides whether a brand new account may come into being, and
getting it wrong creates an unwanted signup rather than handing anybody
somebody else's workspace.
"""

import os

MODE_ENV = "WHICHPORTS_SIGNUP"
ALLOW_ENV = "WHICHPORTS_SIGNUP_ALLOW"

OPEN = "open"
CLOSED = "closed"

# What a person is told, on the login page and on the register page, and what
# the refusal says when somebody posts the form regardless. One string, so the
# promise and the refusal cannot drift apart.
CLOSED_NOTICE = "New accounts are closed at the moment."


def mode() -> str:
    """`open` only when it says exactly that, otherwise `closed`."""
    value = os.environ.get(MODE_ENV, "").strip().lower()
    return OPEN if value == OPEN else CLOSED


def allow_list() -> set:
    """The addresses that may sign up whatever the mode says."""
    raw = os.environ.get(ALLOW_ENV, "")
    parts = raw.replace(",", " ").split()
    return {part.strip().lower() for part in parts if part.strip()}


def is_open() -> bool:
    """Whether anybody at all may sign up. False does not mean nobody can: an
    address on the allow list still may, which is what `may_sign_up` answers."""
    return mode() == OPEN


def may_sign_up(email: str | None) -> bool:
    """Whether this address may create an account right now.

    An empty address is refused rather than treated as a wildcard, which is the
    safe way round and matches `identities.provision` refusing to name an
    account after nothing. Whitespace counts as empty: stripping happens before
    the emptiness check, so a blank-but-not-empty address is refused too rather
    than sailing through while the mode is open.
    """
    email = (email or "").strip().lower()
    if not email:
        return False
    if is_open():
        return True
    return email in allow_list()


def notice() -> str | None:
    """The line to show on the login and register pages, or None when signups
    are open and there is nothing to say."""
    return None if is_open() else CLOSED_NOTICE
