"""Sign in with Google.

Every fact here was read from Google's own documentation on 2026-08-22. The
notes behind each one are in the pull request that added this file, and the two
that change what the code does are stated in place below.

Google is not in the earlier project `app/oidc.py` was reviewed from, so this
is new rather than reviewed across. What was borrowed is the flow shape in
`app/oidc.py`.
"""

from . import oidc

# The only Google URL written down in this codebase. Everything else, the
# authorization endpoint, the token endpoint and the issuer, is read from this
# document, which is what Google asks callers to do.
DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# `openid` for the ID token, `email` because the address is not in the token
# without it and it is what an operator recognises on a screen, `profile` for a
# display name. Nothing else. We are not becoming a client of Google's APIs.
SCOPE = "openid email profile"

# **Google documents two accepted values for `iss`.** Checking only the https
# form is a bug that bites the day the other one arrives, so both are here and
# the comparison is exact against this tuple rather than a prefix test.
ISSUERS = ("https://accounts.google.com", "accounts.google.com")


def subject_of(claims: dict) -> str:
    """The string an account is keyed on: `sub`, and nothing else.

    **Google says so in a warning box**: "you shouldn't use the `email` field in
    the ID token as a unique identifier for a user. Always use the `sub` field."
    An address can be changed, reassigned inside a Workspace domain, or simply
    belong to somebody else later. `sub` cannot.
    """
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise oidc.OIDCError("Google returned no subject to identify the account")
    return subject


def email_of(claims: dict) -> str | None:
    """The address, for showing on a screen and for nothing else.

    It is returned only when `email_verified` is true. That is not because a
    verified address is safe to key on, it is not and `subject_of` above is the
    key, but because an unverified one is not even worth displaying as fact.
    """
    if claims.get("email_verified") is not True:
        return None
    email = claims.get("email")
    return email.strip().lower() if isinstance(email, str) and email else None


PROVIDER = oidc.Provider(
    name="google",
    label="Google",
    discovery_url=DISCOVERY_URL,
    scope=SCOPE,
    env_prefix="WHICHPORTS_GOOGLE",
    subject_of=subject_of,
    email_of=email_of,
    issuers=ISSUERS,
)
