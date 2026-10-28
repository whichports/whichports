# controlplane

The service agents post their host documents to, and the storage the
dashboard reads. This is the internet-facing half of the product, so it is
kept small on purpose: one endpoint, one credential check, one size cap, one
verbatim insert. The agent's half of the channel is `agent/internal/report`.

## Layout

```
app/cli.py        what a command opens: the environment file, then the
                  database, or a refusal. Never a database it invented
app/db.py         SQLite schema and connections, WAL mode
app/store.py      hosts and reports, credential hashing
app/ingest.py     the FastAPI app: POST /api/v1/reports, GET /healthz
app/hosts_cli.py  add, list, revoke, prune, delete hosts from the terminal
app/alerts.py     the dead-man sweep, and its own additive schema
app/notify.py     alert delivery, off unless configured
app/hetzner.py    the Hetzner Cloud provider leg, GET only, off unless configured
app/hetzner_cli.py  show, fetch and print the provider view
app/accounts.py   operator accounts, scrypt hashing, server-side sessions
app/ratelimit.py  the token buckets in front of the login form
app/web_auth.py   GET and POST /login, POST /logout, GET /api/auth/whoami
app/web_pages.py  the login page's HTML, taking its look from site/theme.py
app/users_cli.py  add, list, disable and sign out accounts from the terminal
app/authz.py      may this address be probed: proof, the record of it, expiry
app/authz_cli.py  start a proof, verify it, list, check, revoke
app/dnstxt.py     a stdlib DNS TXT lookup, used by the DNS proof and nothing else
tests/            the contract, tested as an agent would speak it
```

`app/authz.py` is the gate SI-6 rests on. Nothing probes an address without
asking `may_probe` first, and no other module opens its tables, which a test
enforces. The reasoning is in the module docstring rather than here, so there
is one place to read it.

The database is a single SQLite file, `WHICHPORTS_DB` (default
`whichports.db` in the working directory). Backing it up is copying one
file. The dashboard reads the same file; WAL mode keeps the two processes
out of each other's way.

## Run

```
uv sync
uv run uvicorn app.ingest:app --host 127.0.0.1 --port 8410
```

That is a development run and it is deliberately not the production command.
**`controlplane/ops/whichports-ingest.service` is the only place the flags this
runs with in production are written**, so read it there rather than trusting
this line, and expect them to differ. Some of those flags are load-bearing
rather than tuning, and the unit says which and why.

Add a host and get its credential (shown once, only the hash is stored):

```
uv run python -m app.hosts_cli --create-database add almabox
```

`--create-database` is needed only the first time, and only on `hosts_cli` and
`users_cli`. Every command here refuses to run against a database that is not
there rather than making one, because a command that quietly creates a second
database answers about the wrong one. `app/cli.py` has the reasoning and the
two afternoons behind it. Drop the flag once the file exists.

Make an operator account. This is the only way one comes into being: there is
no signup page, for the same reason there is no host self-enrolment. The
password is asked for at the prompt and never taken as an argument, because a
command line is visible in `ps` and lands in shell history.

```
uv run python -m app.users_cli add sysadmin@example.com
uv run python -m app.users_cli list
uv run python -m app.users_cli sign-out sysadmin@example.com   # revoke every session
```

Read the Hetzner Cloud view of one workspace's fleet. The token is the
workspace's own, entered on the Integrations screen and stored per
workspace, and it must be a token with Read permission. With none stored the
command says so and does nothing:

```
uv run python -m app.hetzner_cli show --workspace 1     # fetch and print, write nothing
uv run python -m app.hetzner_cli fetch --workspace 1    # fetch and store one snapshot
uv run python -m app.hetzner_cli latest --workspace 1   # print the stored snapshot
```

## Test

```
uv run pytest
```

## Deploy shape

One systemd unit running uvicorn on 127.0.0.1:8410, behind the existing
Caddy on the production box. The public hostname must be DNS-only at
Cloudflare, not proxied, because agents cannot answer a browser challenge
(the get.whichports.com lesson, RECORD 4.30). Caddy routes `/api/v1/*` to
this service. Errors to agents are status codes only, detail stays in this
service's journal.

Everything else on the same hostname is the dashboard, served by this same
process: `site/app/render_live.py` reads this database and renders the owner's
shell (`site/app/build.py`) with the real fleet, per request, for the
workspace behind the request's session. `app/renderbridge.py` is how a module
from the site tree is importable here at all. No timer, no file on disk, no
resident UI process beyond this one. The Reflex app under `dashboard/` predates this, was
superseded on 2026-08-13 (RECORD 4.34), and is kept as an option on the owner's
word of 2026-09-03. Nothing routes to it.

### Where the login fits

`/login` and `/logout` are served by this process because a login form needs
a fresh CSRF token per render, and the dashboard routes sit beside them: a
request with a live session gets its workspace's page rendered there and
then, and one without is redirected to `/login`.

Caddy does not route `/login` yet, so on the box these paths answer nothing and
basic auth is still the only gate. That Caddyfile change is made on the box
first and mirrored into `ops/caddyfile.reference` in the same pull request, the
rule that file's own header sets.
