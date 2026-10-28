"""Which workspace a row belongs to when nothing says otherwise.

**Two constants in their own file, and the reason is the vantage host.**
`app/authz.py` runs in two places: here, beside the database, and on a prober,
where `ops/deploy-prober.sh` ships five modules and deliberately no `db.py`,
no `store.py` and no database at all. That script checks the five form a
closed import graph and refuses to deploy when they do not.

On 2026-08-23 the workspaces change gave `authz.account_for_workspace` a
single reference to `db.DEFAULT_WORKSPACE_ID`, which made `authz` import `db`,
which broke that closed set. The deploy refused, correctly, and because a
prober deploy is run by hand rather than by CI, nobody found out for five
days: the vantage host sat nine commits behind while every test stayed green
(`docs/RECORD.md` 4.113).

Putting the two constants here and importing them from both sides costs one
small file and keeps three properties that are each worth more than it:

  - the fact still has exactly one owner,
  - `authz` can be read, imported and run on a machine with no database, which
    is what the prober is,
  - `db.py` stays a leaf. Making it import `authz` instead would drag
    `urllib`, `secrets` and `dnstxt` into every module that touches the
    database, to save one file.

`tests/test_prober_module_set.py` runs the deploy script's check on every
commit now, so the next module that reaches for the database fails there
rather than at a deploy nobody runs for a week.
"""

# The workspace every row that predates workspaces was backfilled into, and the
# one the command line works in unless told otherwise. It is 1 rather than a
# name because a workspace id is what a directory and a foreign key hold, and a
# renameable label is not something either of those should depend on.
DEFAULT_WORKSPACE_ID = 1
DEFAULT_WORKSPACE_NAME = "default"
