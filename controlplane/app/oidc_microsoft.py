"""Sign in with Microsoft, Entra ID, the v2.0 endpoints.

Every fact here was read from Microsoft's own documentation on 2026-08-22, and
the sentence each rule rests on is quoted where the rule is. The shape is
`app/oidc_google.py`'s. What is genuinely different is all in this file, and it
is three things:

  - **The account key is the pair `(tid, oid)`, not `sub` and never an
    address.** Microsoft says the tenant "must be part of the key used to access
    the user's data", so a subject on its own is not a key here.
  - **The issuer is not a fixed string.** With a multi-tenant authority the
    metadata carries a template with the tenant left as a placeholder, and the
    check is to substitute the token's own tenant and then compare exactly.
  - **The authority is required configuration with no default**, because it
    decides who in the world can sign in and that is not a decision this file
    gets to take.
"""

import os
import re

from . import oidc

# The authority, which is the `{tenant}` segment in every Microsoft URL below.
#
# **There is deliberately no default here, and adding one would be wrong.**
# Microsoft: "The {issuer} value in the path of the request can be used to
# control who can sign into the application. The allowed values are common for
# both Microsoft accounts and work or school accounts, organizations for work or
# school accounts only, consumers for Microsoft accounts only, and tenant
# identifiers such as the tenant ID or domain name." So `common` is not a
# filter. It lets every Microsoft account on the internet reach the consent
# screen, personal ones included, and a tenant GUID lets in one organisation.
#
# Which of those is right for this product is a decision on the board, in
# Decisions, as "Decide: which Microsoft authority for sign-in, common vs
# organizations vs one tenant".
# Until it is taken this variable is unset, `oidc.is_ready` is False, no button
# appears and `/login/microsoft` answers 404.
AUTHORITY_ENV = "WHICHPORTS_MICROSOFT_TENANT"

# The two words this build accepts. A tenant GUID is the third accepted value
# and is recognised by its shape rather than listed here. Nothing else reaches a
# URL: `consumers` is left out because personal accounts only is not a shape
# this product has a use for, and an authority nobody thought about should not
# be reachable by a typo in a unit file.
AUTHORITY_WORDS = ("common", "organizations")

# Microsoft's v2.0 metadata address, with the authority in the path.
DISCOVERY_TEMPLATE = ("https://login.microsoftonline.com/{authority}"
                      "/v2.0/.well-known/openid-configuration")

# What a multi-tenant metadata document carries as its `issuer`, verbatim,
# braces included: `https://login.microsoftonline.com/{tenantid}/v2.0`. It is a
# template rather than a URL, and this is the placeholder in it.
TENANT_PLACEHOLDER = "{tenantid}"

# The form Microsoft says a v2.0 issuer takes once the tenant is filled in:
# "Validate that the tid claim is a GUID and the iss claim is of the form
# https://login.microsoftonline.com/{tid}/v2.0 where {tid} is the exact tid
# claim."
ISSUER_TEMPLATE = "https://login.microsoftonline.com/{tenant}/v2.0"

# `openid` for the ID token, `profile` because `oid` and `preferred_username`
# are not in the token without it, `email` for the address a screen shows.
# Nothing else, and no `offline_access`, because we want an identity and not a
# client of Microsoft Graph.
SCOPE = "openid profile email"

# 8-4-4-4-12 hexadecimal, which is what Microsoft calls a GUID and what it says
# `oid` and `tid` are. Either case, because the comparison Microsoft publishes
# for the issuer is case-invariant.
_GUID = re.compile(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


def is_guid(value) -> bool:
    """Whether this is a GUID, and nothing that merely contains one."""
    return isinstance(value, str) and _GUID.fullmatch(value) is not None


def authority() -> str | None:
    """Which sign-ins Microsoft is asked to accept, or None when it is not set
    or is not one of the values this build knows.

    An unrecognised value answers None rather than being passed through, so a
    typo cannot build a URL nobody chose. The effect is the same as leaving it
    unset: no button, and `/login/microsoft` answers 404.
    """
    value = os.environ.get(AUTHORITY_ENV, "").strip()
    if value in AUTHORITY_WORDS or is_guid(value):
        return value
    return None


def discovery_url() -> str | None:
    """The v2.0 metadata address for the configured authority, or None when
    there is no authority to put in it."""
    tenant = authority()
    if tenant is None:
        return None
    return DISCOVERY_TEMPLATE.format(authority=tenant)


def issuer_ok(claims: dict, document: dict) -> bool:
    """Whether this token's `iss` is one this server accepts, which for
    Microsoft depends on the token itself.

    **This is the trap in the whole integration, so it is spelled out.** With a
    multi-tenant authority the `issuer` in the metadata document is the literal
    string `https://login.microsoftonline.com/{tenantid}/v2.0`, braces and all.
    An equality check against that can never pass, and the tempting repair, a
    "does it start with login.microsoftonline.com" test, accepts a token from
    any tenant in the world and also accepts
    `https://login.microsoftonline.com.evil.example/...`.

    Microsoft's own algorithm, quoted: "Instead of expecting the issuer claim in
    the token to exactly match the issuer value from metadata, the application
    should replace the {tenantid} value in the issuer metadata with the tenant
    id that is the target of the current request, and then check the exact
    match." And: "Validate that the tid claim is a GUID and the iss claim is of
    the form https://login.microsoftonline.com/{tid}/v2.0 where {tid} is the
    exact tid claim. This validation ties the tenant back to the issuer and back
    to the scope of the signing key creating a chain of trust."

    Both halves are here, in that order, because they are not the same check.
    The first one binds the token to the document this server read. The second
    one binds the issuer's tenant segment to the `tid` the account key is built
    from, which is what stops a token whose `iss` names one tenant and whose
    `tid` names another.

    The substitution looks for the placeholder as the document spells it. If a
    document ever spells it differently the substitution does not happen, the
    comparison fails, and the sign-in is refused, which is the direction to fail
    in.
    """
    tenant = claims.get("tid")
    if not is_guid(tenant):
        return False
    issuer = claims.get("iss")
    if not isinstance(issuer, str) or not issuer:
        return False

    published = document.get("issuer")
    if not isinstance(published, str) or not published:
        return False
    if published.replace(TENANT_PLACEHOLDER, tenant) != issuer:
        return False

    if ISSUER_TEMPLATE.format(tenant=tenant) != issuer:
        return False

    # With a tenant GUID as the authority, one organisation is the whole point,
    # so the token's tenant has to be that one. Microsoft's metadata for a
    # single tenant is expected to name that tenant in its issuer, which would
    # make this check say the same thing twice, but that expectation was never
    # confirmed against a real tenant's document, so it is checked here rather
    # than assumed there.
    configured = authority()
    if is_guid(configured) and configured.lower() != tenant.lower():
        return False
    return True


def subject_of(claims: dict) -> str:
    """The string an account is keyed on: the tenant and the object id, joined.

    **Not `sub`, and never an address.** Microsoft: "use the immutable claim
    values tid and oid as a combined key for application data and determining
    whether a user should be granted access", and "the tid claim must be part of
    the key used to access the user's data". The reason is in Microsoft's own
    example: the same `sub` under two different issuers is two different people,
    because a subject is read inside the tenant that issued it. The same follows
    for `oid`, which Microsoft says a user has a different one of in every
    tenant they exist in: "they're considered different accounts, even though
    the user logs into each account with the same credentials".

    The join is `tid:oid` and both halves are checked to be GUIDs before it is
    built. A GUID is hexadecimal and hyphens, so it can hold no colon, so there
    is exactly one way to read the result and no pair of accounts can produce
    the same string.

    Lowercased, because the same tenant and the same object are one account and
    not two. Microsoft's published issuer comparison is case-invariant, so
    letting a case difference mint a second identity would be our invention.
    """
    tenant = claims.get("tid")
    obj = claims.get("oid")
    if not is_guid(tenant):
        raise oidc.OIDCError("Microsoft returned no tenant to identify the account")
    if not is_guid(obj):
        raise oidc.OIDCError("Microsoft returned no object id to identify the account")
    return f"{tenant.lower()}:{obj.lower()}"


def email_of(claims: dict) -> str | None:
    """The address, for showing on a screen and for nothing else.

    **Microsoft says never to decide anything with this, in as many words.** On
    `email`: "This value isn't guaranteed to be correct and is mutable over
    time. Never use it for authorization or to save data for a user." On
    `preferred_username`: "Its value is mutable and might change over time.
    Since it's mutable, this value can't be used to make authorization
    decisions. It can be used for username hints and in human-readable UI as a
    username." And in a warning of its own: "These claims aren't unique and can
    be controllable by tenant administrators or sometimes users, which make them
    unsuitable for authorization decisions. They're only usable for display
    purposes."

    That last clause is the mechanism, in nine words. An administrator controls
    the addresses in a tenant they own, and anybody can create a tenant.
    Microsoft published an advisory about the attack in June 2023, which
    `app/identities.py` quotes.

    Unlike Google there is no `email_verified` here to gate on, so what comes
    back is shown as it arrived and read for nothing. `preferred_username` is
    the fallback because Microsoft only sends `email` in some configurations,
    and Microsoft says it "could be an email address, phone number, or a generic
    username", so it is a label under a label's rules and not an address we
    would ever write to.
    """
    for name in ("email", "preferred_username"):
        value = claims.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return None


PROVIDER = oidc.Provider(
    name="microsoft",
    label="Microsoft",
    # The address is not fixed, because the authority is in it. `discovery_url`
    # below is the function that builds it, and it answers None until the
    # authority is configured.
    discovery_url="",
    scope=SCOPE,
    env_prefix="WHICHPORTS_MICROSOFT",
    subject_of=subject_of,
    email_of=email_of,
    issuer_ok=issuer_ok,
    discovery_url_of=discovery_url,
    # The authority, which decides who may sign in at all and has no default.
    # Not a secret, so `users_cli providers` prints it in full: reading it back
    # is the point, because a typo in it reads as "not configured" and looks
    # exactly like a credential that never arrived.
    extra_env_vars=(AUTHORITY_ENV,),
)
