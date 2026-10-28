"""Which identity providers this build knows about.

A module of its own for two reasons. The command line needs the list and must
not import `app/web_auth.py` to get it, because that would pull FastAPI into a
terminal command. And adding a provider should be one line here plus its own
module, rather than an edit inside a request handler.

A provider being in this list does not put it on the login page.
`oidc.is_ready` decides that, and it needs both halves of the client credential
and a base URL to come back to. So an unconfigured build shows a plain email and
password form.
"""

from . import oidc_google, oidc_microsoft

PROVIDERS = {p.name: p for p in (
    oidc_google.PROVIDER,
    oidc_microsoft.PROVIDER,
)}
