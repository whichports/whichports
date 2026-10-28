"""One workspace's dashboard, rendered from the database when a browser asks.

## Why it renders per request rather than reading a file

Until 2026-08-25 this module read pages that `whichports-render.timer` wrote
once a minute (the owner's decision, `docs/RECORD.md` 4.102 ends that). The
minute was the problem: every action on the page talks to the admin routes and
then reloads, and a reload inside the minute showed the page from before the
action. Rendering when asked means what the browser gets back is always the
database as it is now, which is what "an action shows its result at once"
requires end to end rather than only client side.

The renderer itself did not move. `site/app/render_live.py` still owns the
page, this module only calls it, and how a module from the site tree can be
called from here at all is `app/renderbridge.py`, which is worth reading
before changing anything about these imports.

## The guard that survives from the file-reading days

**A workspace id is turned into an integer before it is used.** There is no
path for it to traverse any more, and the check stays anyway, because the id
scopes every database read the render makes: `bool` is refused by name since
`True` is `1` in Python and a flag arriving here would quietly render
workspace 1's page for somebody else. A string is refused even when it is all
digits, because the only caller reads an INTEGER column and anything else
arriving here is a bug worth hearing about.
"""

import os
from datetime import datetime, timezone

from . import adminstats, db, feedback_routes, proberproofs, renderbridge


class WorkspaceIdError(ValueError):
    """A workspace id that is not the positive integer the accounts table holds."""


def _as_workspace_id(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WorkspaceIdError(
            f"a workspace id is an integer, not {type(value).__name__}")
    if value < 1:
        raise WorkspaceIdError("a workspace id is at least 1")
    return value


def page(workspace_id, now=None, admin=False, viewing=None, lookup=None,
         csrf="") -> str:
    """One workspace's dashboard, rendered from the database now.

    `admin` adds the Admin screen, which is the service-wide numbers rather
    than this workspace's. **It is a decision the caller has already taken**,
    from the account behind the session cookie, and it reaches here as a plain
    flag so nothing in this module or below it has to know what an account is.
    False leaves the screen and its nav entry out of the HTML entirely.

    `viewing` is `(workspace_id, name)` when an admin is looking into somebody
    else's workspace. **It is a label, not a decision.** `workspace_id` above
    is what every read on this page is scoped by, and the caller has already
    decided both together and checked the flag before doing so. Passing one
    without the other would draw a banner naming a workspace the page is not
    showing, so `page_for_workspace` below is the only thing that sets either.

    `lookup` is an address the admin typed into the lookup, or None, and
    `csrf` the page's form token, which only the lookup's form carries. Both
    are nothing on every page but an admin's own.

    `now` is the request time and defaults to it, so the footer's stamp is
    when this page was asked for. The commit half of that stamp still comes
    from `/srv/controlplane/DEPLOYED_COMMIT` the way `render_live.py`
    documents, read on every render, so a deploy shows in the next refresh.

    Raises WorkspaceIdError for anything that is not a positive integer, and
    lets a renderer fault surface as the error it is: a dashboard that cannot
    be built is a fault to hear about, never a blank page.
    """
    number = _as_workspace_id(workspace_id)
    when = now or datetime.now(timezone.utc)
    render_live = renderbridge.load()
    # Counted only when the screen is going to be drawn, so an ordinary page
    # load costs nothing it does not use.
    numbers = adminstats.collect(db.db_path(), now=when) if admin else None
    # The address lookup (docs/screens/admin/SPEC.md, his `lookup yes` of
    # docs/record 4.425): read on the same read-only connection, and the
    # address goes nowhere but into this one page. Never without the flag.
    if numbers is not None and lookup is not None:
        numbers["lookup"] = adminstats.address_lookup(db.db_path(), lookup)
    # The Feedback window's To line: where a message goes, decided by the
    # setting that says who this instance's probers are
    # (app/feedback_routes.py, docs/screens/feedback/BRIEF.md).
    # On an instance that uses our probers an address row reads proved only
    # when our side holds the address too (app/proberproofs.py).
    return render_live.render(db.db_path(), now=when, workspace_id=number,
                              admin=numbers, viewing=viewing, csrf=csrf,
                              feedback_to=feedback_routes.destination(os.environ),
                              with_prober_api=proberproofs.configured(os.environ))


class WorkspaceMissing(LookupError):
    """No workspace with that id."""


def page_for_workspace(workspace_id, now=None) -> str:
    """One workspace's dashboard, rendered for an admin looking into it.

    **The caller has already checked the admin flag.** This function does not
    know what an account is and must never be reached without that check, which
    is why it lives here beside `page` rather than being a branch inside it: a
    branch invites a caller to pass a flag it computed wrongly.

    The Admin screen is deliberately absent from this render. It is the whole
    service's numbers and it belongs on your own page, not layered over
    somebody else's, and leaving it out means the nav on this page is the nav
    they have.

    Raises WorkspaceMissing for an id nothing matches, so a stale link is a
    404 rather than an empty fleet that reads as a customer with no servers.
    """
    number = _as_workspace_id(workspace_id)
    con = db.connect()
    try:
        db.init(con)
        row = db.workspace_by_id(con, number)
    finally:
        con.close()
    if row is None:
        raise WorkspaceMissing(f"there is no workspace {number}")
    return page(number, now=now, admin=False,
                viewing=(number, row["name"]))
