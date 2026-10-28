# Running whichports yourself

This directory runs a whole whichports on one Linux server with Docker
Compose: the control plane your agents report to, the dashboard, and the
scheduled jobs. What your agents read stays on your server. The view from
outside comes from our probers, which your instance asks through an API.

This file is how an instance is installed, upgraded, backed up and restored.

## What runs

| Container | What it does | Network |
|---|---|---|
| `controlplane` | The API agents post to, and the dashboard | this machine's own, listening on `127.0.0.1:8410` |
| `worker` | The scheduled jobs: the sweep every five minutes, a probing pass every ten minutes and every hour, a backup nightly at 03:17 UTC, the CVE check's security data daily at 04:41 UTC, the responder to Scan now, and our prober list every fifteen minutes | a Docker network of its own, nothing listening |
| `caddy` | The front door on 443, with the certificate. Optional | this machine's own |

The worker runs the same commands at the same cadences as the systemd timers
on our own server, because it reads them from the same unit files
(`controlplane/ops`, `ops/cve`, `selfhost/worker.py`). Taking our prober list is the one
job it has that our server does not, because our server reaches the probers
directly.

## Before you install

**It is for a Linux server, not Docker Desktop.** It needs:

- Docker Engine with the Compose plugin. `docker compose version` answers
  when the plugin is there. From the distribution's own packages the plugin
  is `docker-compose-v2` on Ubuntu 26.04 and `docker-compose` on Debian 13.
  On Debian 13 the `docker` command is a package of its own, `docker-cli`,
  which `docker.io` only recommends, so name it when you install. On Ubuntu
  26.04 name `docker-buildx` too, which Compose builds with: without it,
  Compose warns that buildx is not installed and builds all the same.
- git, for the clone and for the commit the dashboard names.
- A DNS name whose A record points at the server, and an AAAA record only if
  the server has that IPv6 address.
- Port 443 open from the internet, so Caddy can get its certificate there.
  Port 80 need not be open. Nothing listens on it, so the address to type
  starts with `https://`. Caddy must have port 443 from the internet: the
  certificate authority's check comes to 443, over TLS, and Caddy answers it
  itself. A server behind a proxy or load balancer that ends TLS is not for
  the one-line install: install by hand, with Your own proxy.
- Outbound HTTPS. While it builds: Docker Hub and ghcr.io for the three base
  images, and pypi.org and files.pythonhosted.org for the Python packages.
  While it runs: the certificate authority, which is Let's Encrypt, our
  prober API, security-tracker.debian.org and
  security-metadata.canonical.com once a day for the CVE check, and what you
  connect yourself, such as a mail relay or a chat webhook.

It has run on these, on x86_64, on a server with 2 CPUs and 4 GB of memory:

| Distribution | Docker, Compose | Installed from |
|---|---|---|
| Ubuntu 26.04 | 29.1.3, 2.40.3 | Ubuntu's own packages |
| Debian 13 | 26.1.5, 2.26.1 | Debian's own packages |
| AlmaLinux 10 | 29.8.2, 5.6.0 | Docker's repository, by Docker's page for CentOS |
| Fedora 44 | 29.8.2, 5.6.0 | Docker's repository |
| Ubuntu 24.04 | 29.8.2, 5.6.0 | Docker's repository |

The build took 15 to 18 seconds there and added 0.3 to 0.7 GB to the disk,
and the whole server used at most 700 MB of memory while it built.

On AlmaLinux 10 and Fedora 44 it ran with SELinux enforcing and firewalld on.
Docker's daemon ran there without its SELinux option, as it is installed, and
the stack's processes ran as `spc_t`, a type the container policy leaves
unconfined. The audit log held no denial.

Podman was tried once, on AlmaLinux 10 with Podman 5.8.2: `podman compose`
built and started the control plane and the worker, using Docker's Compose
plugin. Caddy was not tried under Podman, so these steps are for Docker.

**The control plane and Caddy share the server's network, so they can reach
services that listen only on the server's own loopback. Give whichports a
small server or VM of its own.** They share it because the control plane
believes the address an agent reported from only when the proxy in front of it
connects over loopback, and that address is how a server proves it holds its
own address. A proxy in a separate container network is not loopback.

**Nothing is published through Docker.** A port Docker publishes is routed
before your firewall's rules are applied
([Docker and ufw](https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-and-ufw)).
Here Caddy listens on 443 like any program on the server, so the rules you
already have apply to it. With ufw, with firewalld and with nftables closed
to it, nothing answered from outside while Caddy was listening, and it
answered once it was opened: `ufw allow 443/tcp`, or `firewall-cmd
--add-service=https` and the same with `--permanent` to keep it across a
reboot. Port 80 stays closed.

**Our API learns the public addresses of your servers.** Probing them requires
it. Each agent sends them to our API after a collection, with your instance's
proof key, so we can check that your instance holds an address before our
probers touch it. An address you prove by DNS TXT or a token file goes to our
API as well, with your instance's API key, when you start the proof, and our
side reads the record or the file itself when you verify it. For another
address of a server whose file already holds a token, that token goes with it.
An address you revoke goes to our API first, the same way, unless another
workspace of your instance holds it too. No document, no host name and no
measurement history leaves your server. One more thing leaves, and only when somebody sends it: a message
typed into the dashboard's Feedback window. It is the words as the window
shows them, and beside them the kind, the screen and the version. What the
words say is up to the person who types them, and nothing is added to them.
It goes with your instance's API key, like every batch your instance sends.
On an instance with no prober lines in `.env` the message is kept in its own
database and nothing is sent. What our side keeps about an instance:

- its name, and its two keys as hashes
- the addresses its servers proved they hold. A proof by the agent
  lapses an hour after the agent last renewed it. One by DNS TXT or a token
  file lasts thirty days and is read again every day. Lapsed ones are kept as
  the history
- of each proof by DNS TXT or a token file your instance starts, the address,
  the way, a hash of the token and when, and once it is proved, the token as
  our side read it. Kept like the proofs
- a batch of ports to probe and its answer, until your instance collects the
  answer, and never longer than fifteen minutes
- how many connections it asked for, for the hour that count is used in
- for thirty days, one line per day, prober and address, saying a batch
  could reach it and how many connections that was. No port and no result.
  It is what lets us answer an abuse report about our probers
- a feedback message: its words with the kind, the screen and the version,
  which instance sent it and when it arrived, until we delete it. No
  address, and no name or account of the person who wrote it

A batch with its answer and the count of connections are not in a snapshot:
each night's copy of the database is emptied of both before it is kept.
Everything else in this list is also in those nightly snapshots, fourteen of
them, so a thing we delete is gone from our server fourteen nights later. Two
more machines of ours each fetch the newest snapshot every night and keep
fourteen copies. A copy there is gone fourteen nights after its snapshot was
made, as on our server, and later than that when our server made no new
snapshot or that machine was off. A snapshot we copy off the server by hand is
kept until we delete that copy.

**Alerts go to public addresses only, unless you say otherwise.** A chat
server or a webhook receiver inside your own network has a private address,
and an alert to one is refused. To allow it, set
`WHICHPORTS_ALERTS_TO_PRIVATE_ADDRESSES=yes` in `.env`. An alert may then go
to an address in `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`
and `100.64.0.0/10`, the range Tailscale and carrier networks use. The
server's own loopback, link-local addresses and every other address that is
not a public one stay refused either way. What turning it on means: anybody
who may add a channel on your instance can then make it send an alert to an
address inside your network, and sees whether something answered there. Mail
is not part of this: a mail relay on a private address works without it.

**One capability in the whole stack.** Caddy holds `NET_BIND_SERVICE`, to bind
443 as an unprivileged user. Every container runs as that unprivileged
user with a read-only filesystem and every other capability dropped, and no
container is given the Docker socket.

## Install

On the server, with Docker, its Compose plugin and git installed, and your
domain's A record pointing at the server. On Ubuntu 26.04 the packages are:

```
sudo apt install docker.io docker-compose-v2 docker-buildx git
```

On Debian 13:

```
sudo apt install docker.io docker-cli docker-compose git
```

Then the install. It runs as root and installs to `/opt/whichports`:

```
curl --proto '=https' --tlsv1.2 -fsSL https://get.whichports.com/selfhost.sh | sudo sh
```

It asks four things: your domain, your invitation, which is one line, an
email address and a password for your account. Each answer is checked before
anything is changed. Then it says what it will do with them, the host of our
probers among them, and goes on only when you type yes. Then it clones
the repository into `/opt/whichports`, writes `/opt/whichports/selfhost/.env`
readable by root only, builds and starts the stack, waits until the control
plane and Caddy read `healthy` and no container restarts for ten seconds, and
makes your account. Open `https://<your domain>/`
and sign in. The commands in the rest of this file run in
`/opt/whichports/selfhost`.

Run again, it changes nothing it does not have to: it uses the folder it
made, leaves an `.env` that holds the same answers, and makes no second
account. When `.env` holds anything else, edited by hand or written with
other answers, it stops before changing anything and says so. Before it asks
anything, it stops when another program holds port 443 or 8410, or when a
stack named whichports runs from another folder. It also stops
when anybody but root owns or may write any part of `/opt/whichports`, or
when git sees a change or a file in it that the release does not have.

`selfhost/install.sh` is the script that line runs. The copy that is served
names one release, a tag and its commit, and builds nothing but that commit.

### By hand

The same install, one step at a time.

```
git clone <the repository> whichports
cd whichports/selfhost
cp env.example .env
chmod 600 .env
```

Edit `.env`. `WHICHPORTS_DOMAIN` is the one line you must set. Your
invitation is one line, which goes after `WHICHPORTS_PROBER_INVITE=`. The
file will hold your mail relay's password and both prober keys, which is why
only you may read it.

```
WHICHPORTS_COMMIT=$(git rev-parse --short=12 HEAD) docker compose up -d --build
docker compose ps
```

If your user is not in the `docker` group the command needs `sudo`, and the
variable goes after it. In front of `sudo` the build still succeeds and the
dashboard names no commit.

```
sudo WHICHPORTS_COMMIT=$(git rev-parse --short=12 HEAD) docker compose up -d --build
```

`controlplane` reads `healthy` within a minute. How soon depends on your
Docker: 22 seconds on 29.1.3, and 45 on 26.1.5, which runs its first health
check 30 seconds after the container starts.

Make your account, which asks for
a password twice: at least 12 characters, with a number and a
special character.

```
docker compose exec controlplane python -m app.users_cli --create-database add you@example.com
```

`--create-database` is for this first command only. Open
`https://<your domain>/` and sign in. The first load can take a moment,
because Caddy has to get its certificate first, and `docker compose logs
caddy` says where it is. The footer of the dashboard names the commit you
built.

### After the install

With the invite line set, or the three prober lines of an older invitation,
the worker takes the list of our probers from our API by itself: within two
minutes of starting, and every fifteen minutes after, so a prober we add
reaches your instance without you doing anything. Without them the worker
schedules no probing pass and says so in one line when it starts. The
dashboard shows what your agents read, and each port's view from outside
reads `not tested`.

Then add a server from the dashboard. The install command it prints enrols
that server to your instance, and installs the agent package from
`get.whichports.com`, the one place it is published.

After a reboot the stack comes back by itself when Docker starts at boot,
and `systemctl is-enabled docker` says whether it does. On Ubuntu and Debian
the Docker packages enable it when they are installed. On AlmaLinux and
Fedora they neither start nor enable it, and this does both:

```
sudo systemctl enable --now docker
```

The dashboard answered again about half a minute after the reboot was asked.

## Your own proxy

To put a reverse proxy you already run in front, remove the line
`COMPOSE_PROFILES=caddy` from `.env` before the first `docker compose up`. If
our Caddy is already running, take it away with `docker compose rm -sf caddy`.
The only socket the stack then opens is the control plane on
`127.0.0.1:8410`.

Your proxy has to run on the same server and connect to that address, for the
loopback reason above. What it must do, and `selfhost/Caddyfile` is the worked
example of each:

- Send every request for your domain to `127.0.0.1:8410`.
- Set `X-Forwarded-For` to exactly one address, the client's. A proxy that
  appends to a list it received makes every agent's proof fail, because the
  control plane refuses a list rather than choosing from it.
- Set `X-Forwarded-Proto` to `https`.
- Not pass `/metrics` to the outside. It counts every server in the instance
  and the control plane asks for no credential there.
- Add `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: no-referrer` to the dashboard's answers, and leave out
  the `Server` header. The control plane sets none of them itself.
- Serve `/fonts/*`, `/favicon.svg`, `/favicon-32.png` and `/robots.txt` from
  files. Copy them out once, and again after an upgrade:
  `docker compose cp controlplane:/srv/whichports/app ./whichports-assets`

## The CVE check's data

Once a day at 04:41 UTC the worker downloads Debian's security tracker file
from security-tracker.debian.org and Canonical's OSV file from
security-metadata.canonical.com, each one whole, and builds from them the
four small files the CVE check reads, in the `cve` volume. Nothing about your
servers or their packages is in those requests. A day it fails, the files of
the day before are used. After three days without a build every port reads
`not checked`. A stack that was down at 04:41 builds when it comes back. On a
new install the worker builds it two minutes after it starts, and a restart
builds again only when the files are not there. To build it again now:

```
docker compose exec worker python selfhost/worker.py once whichports-cve.service
```

## Upgrade

Take a backup, pull, and build again. One refresh of the dashboard then names
the new commit in its footer.

```
docker compose exec worker python selfhost/worker.py once whichports-backup.service
git pull
WHICHPORTS_COMMIT=$(git rev-parse --short=12 HEAD) docker compose up -d --build
```

An instance the one line installed stands on a release tag, where `git pull`
has no branch to follow. Take the backup as above, move it to the new tag, and
build again as above, as root, in `/opt/whichports/selfhost`:

```
sudo git -C /opt/whichports fetch --tags
sudo git -C /opt/whichports checkout <the new tag>
```

The database is upgraded by the control plane itself the first time it is
used. Your settings stay in `.env`, which git never touches. An `.env` with
the three prober lines of an older invitation keeps working as it is. Its
`WHICHPORTS_HTTP_PORT` line is no longer read: Caddy listens on 443 alone,
and an address typed with `http://` gets no answer.

## Backup

The worker takes one snapshot a night at 03:17 UTC, checks that it opens as a
database, and keeps fourteen. A stack that was down at 03:17 takes its
snapshot when it comes back. To take one now:

```
docker compose exec worker python selfhost/worker.py once whichports-backup.service
```

The snapshots live in the `backups` volume on the same server, so they do not
survive losing the server. Copy them somewhere else:

```
docker compose cp worker:/var/backups/whichports ./whichports-backups
```

Each one is a gzipped SQLite file holding every document your agents sent, so
keep the copies as private as the server.

`.env` is not in a snapshot. Keep a copy of it with them.

## Restore

See which snapshots there are, while the stack runs:

```
docker compose exec worker ls /var/backups/whichports
```

Then stop the stack, put one back, start it.

```
docker compose stop
docker compose run --rm --no-deps -T worker python selfhost/restore.py whichports-20261001T031700Z.db.gz
docker compose up -d
```

A bare name is a snapshot in the `backups` volume. For a copy you kept
somewhere else, give it on standard input:

```
docker compose run --rm --no-deps -T worker python selfhost/restore.py - < whichports-20261001T031700Z.db.gz
```

The restore opens the snapshot and checks it before it changes anything. The
database it replaced is kept beside the new one, named
`whichports.db.before-restore-<time>`, until you delete it. What you lose is
what arrived after the snapshot. Your agents report again within fifteen
minutes, so the fleet fills back in and only the history has a gap.

On a new server, install by hand as above with the `.env` you kept, and
make no account. Then stop the stack, give it your copy, and start it. Your
account signs in with the password it had.

```
WHICHPORTS_COMMIT=$(git rev-parse --short=12 HEAD) docker compose up -d --build
docker compose stop
docker compose run --rm --no-deps -T worker python selfhost/restore.py - < whichports-20261001T031700Z.db.gz
docker compose up -d
```

## Settings

All in `selfhost/.env`. `env.example` lists them with what each is for.

| Setting | What it does | Default |
|---|---|---|
| `WHICHPORTS_DOMAIN` | The name the dashboard answers on | none, required |
| `COMPOSE_PROFILES` | `caddy` runs our Caddy. Remove the line for your own proxy | `caddy` |
| `WHICHPORTS_HTTPS_PORT` | Where Caddy listens on the server. Another port only where something forwards 443 to it as it is | 443 |
| `WHICHPORTS_INGEST_PORT` | Where the control plane listens on `127.0.0.1` | 8410 |
| `WHICHPORTS_PROBER_INVITE` | Our probers: your invitation, one line that starts with `whpinvite1_` | empty |
| `WHICHPORTS_PROBER_API`, `WHICHPORTS_PROBER_API_KEY`, `WHICHPORTS_PROBER_PROOF_KEY` | Our probers as three lines, the way an invitation used to come. All three or none, and none beside the invite line | empty |
| `WHICHPORTS_ALERT_TO` and the `WHICHPORTS_SMTP_*` lines | Alert mail. Without a recipient nothing is sent | empty |
| `WHICHPORTS_ALERTS_TO_PRIVATE_ADDRESSES` | `yes` lets an alert go to a private address. Any other value stops the stack at start | not set |

When something else already holds a port Caddy needs, `docker compose up -d`
still says `Started`. Caddy then restarts over and over: `docker compose ps`
reads `restarting` for it, and `docker compose logs caddy` names the address
that is in use. A change to `.env` takes effect with `docker compose up -d`.

## Looking at it

```
docker compose ps
docker compose logs -f worker
docker compose logs -f controlplane
docker compose logs -f caddy
```

Every job the worker runs is one line when it starts and one when it ends,
with its exit code, and the job's own output in between.

## A lost password

A reset link is a mail, so with no mail relay set there is none. Set a new
password from the server. It asks twice, and it signs that account out
everywhere:

```
docker compose exec controlplane python -m app.users_cli passwd you@example.com
```

## Taking it off the server

```
docker compose down
```

That removes the containers and keeps the five volumes, so
`docker compose up -d` brings the same instance back.

To take the instance off for good, take the agents off first. Your servers'
agents prove their addresses to our API with your instance's proof key, not
through your instance, and they go on doing so after the stack is gone. On
every server that reports to this instance:

```
sudo whichports-uninstall
```

Then take the stack down and delete its data as well:

```
docker compose down -v
```

That deletes the database, the snapshots, the CVE check's data and Caddy's
certificate, and it cannot be undone. If you took `COMPOSE_PROFILES=caddy` out of `.env` after our
Caddy had run, its two volumes stay, and the certificate's key is in one of
them. Remove them by name:

```
docker volume rm whichports_caddy_data whichports_caddy_config
```

The folder you installed from stays, `/opt/whichports` for the one-line
install, and so does its `.env` with both keys. Last, write to
hello@whichports.com and ask us to end your instance. Then both its keys and
every proof it made end at once, and no agent and no `.env` can use them
again. There is no undo: an instance that comes back gets a new invitation.

## The images

Each base image is a dependency, pinned by digest in `selfhost/Dockerfile`.

`python`, `python:3.12.14-slim-trixie`. The control plane is Python, and this
is Python's official image on Debian's slim base. 3.12.14 is the interpreter
our gate runs the tests on before every commit, and a test holds the two
equal, so an instance runs the Python the tests ran on. The slim variant leaves out compilers and documentation, which
nothing here uses, since every package installs from a prebuilt wheel.

`uv`, `ghcr.io/astral-sh/uv:0.12.19`. Used in the build stage and not present
in the image that runs. The control plane's dependencies are locked in
`controlplane/uv.lock`, a format pip does not read. uv exports exactly the
locked versions with their hashes and installs them without resolving
anything. Reflex, the superseded dashboard framework in that lock, is left
out with the packages only it needs, so the image holds fourteen packages:
FastAPI, uvicorn, segno and what those three require.

`caddy`, `caddy:2.11.4-alpine`. The reverse proxy in front, the same program
our own server runs. It gets and renews the certificate by itself, which is
the reason to have it at all, and it is the one image you can leave out by
using your own proxy.

## Checking a change to this directory

`python3 selfhost/smoke.py` builds the stack from a clean tree, brings it up,
checks it and takes it down. Its docstring lists what a pass means. It runs
before every commit that touches this directory, a Dockerfile, the Compose
file, `controlplane/uv.lock` or the worker. The gate runs the tests beside it,
which need no Docker.

`python3 selfhost/prove_install.py ubuntu:26.04` runs the install line's
script for real in a container of that system, with that system's own
Docker and Compose commands talking to the Docker on the machine that runs
it, and reads back what it made. Its docstring says what that does and does
not prove. `selfhost/test_install.py` is the half the gate runs.

`python3 selfhost/e2e/run.py` runs the prober API end to end on one machine:
an instance, a second control plane playing our side, a vantage and two
servers with the agent. It shows a pass through the API and every refusal,
and its docstring and `selfhost/e2e/compose.yaml` say what stands in for
what. It needs Docker, and Go to build the agent.
