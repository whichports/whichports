# The images a self-hosted whichports runs. Built from the repository root:
#
#   docker compose -f selfhost/compose.yaml build
#
# Two targets. `controlplane` is the ingest, the dashboard renderer and the
# worker, the same code /srv/controlplane holds on the production box, laid
# out at the same paths so the unit files run unchanged. `caddy` is the
# optional front door with the dashboard's fonts and icons beside it.
#
# Every base image is pinned by the digest of its multi-platform index, so
# the same line resolves to the amd64 or the arm64 image on the machine that
# builds it, and nothing changes under a tag. Each one is a dependency, and
# selfhost/README.md says why each is worth having.
#
# Nothing in here holds a secret. Configuration arrives at run time from the
# env file Compose reads (selfhost/env.example), and the allowlist in
# Dockerfile.dockerignore keeps everything else in the repository out of the
# build context.

# ------------------------------------------------------------------ build
# uv reads uv.lock, which pip cannot. It runs here and is not in the final
# image.
FROM python:3.12.14-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.19@sha256:04d046b13e60d6bcec73cbc5e1cad25d680dea90c8573340950a0ac2d1aef424 /uv /usr/local/bin/uv
WORKDIR /build
COPY controlplane/pyproject.toml controlplane/uv.lock ./
# Exactly the locked versions, each checked against its hash, with no
# resolving. Reflex is pruned with everything only it needs: it is the
# superseded dashboard (docs/RECORD.md 4.34), nothing in controlplane/app
# imports it, and it would bring about thirty packages along. Prod's own
# virtualenv keeps it. selfhost/test_static.py holds this line as it is, and
# selfhost/smoke.py compares the built image's packages with the export.
RUN uv export --frozen --no-dev --prune reflex --no-emit-project \
        --no-header --no-annotate -o requirements.txt \
    && python -m venv --without-pip /srv/controlplane/.venv \
    && uv pip install --python /srv/controlplane/.venv/bin/python \
        --require-hashes --no-deps --only-binary :all: -r requirements.txt

# ----------------------------------------------------------------- assets
# The dashboard's fonts, icons and robots.txt, made by the same function that
# makes them for our own deploy (site/app/build.py, write_dist). site/app/dist
# is build output and a clean checkout does not have it, which the first run
# of selfhost/smoke.py found. The sample page it also writes is not wanted.
FROM python:3.12.14-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS assets
COPY site/theme.py /site/theme.py
COPY site/fonts /site/fonts
COPY site/app /site/app
WORKDIR /site/app
RUN python -c "import pathlib, build; build.write_dist('', dist=pathlib.Path('/assets'))" \
    && rm /assets/index.html

# ------------------------------------------------------------------ caddy
FROM caddy:2.11.4-alpine@sha256:6aeddd44c3078b0f9a35206472a11420648a79c184603ef95957d0a20044cb2b AS caddy
# The files the rendered pages reference by path. On the box they live in
# /srv/whichports/app and Caddy serves them, so here too.
COPY --from=assets /assets /srv/whichports/app
COPY selfhost/Caddyfile /etc/caddy/Caddyfile
# Caddy runs as an unprivileged user, the same id the control plane uses. The
# upstream image runs it as root. On the machine's own network root is the
# worse thing to be, because local services that check who is calling see
# uid 0. Its one capability, binding 443, comes from the file
# capability the upstream image already sets on the binary.
#
# That costs one flag: compose.yaml cannot set no-new-privileges on this
# container, because the kernel ignores file capabilities under it (measured
# 2026-10-01: with the flag, "permission denied" on port 80). So the other
# way to gain privileges is closed here instead: no file in the image keeps a
# setuid or setgid bit. selfhost/smoke.py checks both.
RUN addgroup -S -g 10001 whichports \
    && adduser -S -D -H -u 10001 -G whichports -s /sbin/nologin whichports \
    && mkdir -p /data /config \
    && chown whichports:whichports /data /config \
    && find / -xdev -type f -perm /6000 -exec chmod a-s {} +
USER whichports

# ----------------------------------------------------------- controlplane
FROM python:3.12.14-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS controlplane
# One unprivileged user for both containers. A fixed id, so the volumes keep
# their owner across rebuilds. The three directories are the volumes' mount
# points, made here so a new volume starts owned by this user.
RUN groupadd --system --gid 10001 whichports \
    && useradd --system --uid 10001 --gid 10001 --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin whichports \
    && install -d -o whichports -g whichports -m 0700 \
        /var/lib/whichports-controlplane /var/backups/whichports \
        /var/lib/whichports-cve
COPY --from=build /srv/controlplane/.venv /srv/controlplane/.venv
# What ops/deploy-controlplane.sh ships, at the paths it ships them to.
COPY controlplane/app /srv/controlplane/app
COPY controlplane/ops /srv/controlplane/ops
COPY controlplane/pyproject.toml controlplane/uv.lock /srv/controlplane/
COPY site/theme.py /srv/controlplane/site/theme.py
COPY site/app /srv/controlplane/site/app
COPY selfhost/worker.py selfhost/restore.py /srv/controlplane/selfhost/
# The CVE check's daily build, the unit pair ops/cve/install-on-the-box.sh
# puts on our box, at the same place beside the control plane as in a
# checkout. The worker runs it from there.
COPY ops/cve/whichports-cve.service ops/cve/whichports-cve.timer /srv/ops/cve/
# The dashboard's fonts and icons, for an install whose own proxy serves them
# instead of our Caddy (selfhost/README.md).
COPY --from=assets /assets /srv/whichports/app
# The commit, for the dashboard's footer, so one refresh after an upgrade
# says which code is running. The renderer prints only hex from this file.
ARG WHICHPORTS_COMMIT=
RUN if [ -n "$WHICHPORTS_COMMIT" ]; then \
        printf '%s\n' "$WHICHPORTS_COMMIT" > /srv/controlplane/DEPLOYED_COMMIT; \
    fi \
    && /srv/controlplane/.venv/bin/python -m compileall -q \
        /srv/controlplane/app /srv/controlplane/site /srv/controlplane/selfhost
# The virtualenv first on PATH, so `docker compose exec controlplane python
# -m app.users_cli` is the control plane's Python and not the base image's.
ENV WHICHPORTS_DB=/var/lib/whichports-controlplane/whichports.db \
    PATH=/srv/controlplane/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv/controlplane
USER whichports
CMD ["/srv/controlplane/.venv/bin/python", "selfhost/worker.py", "exec", "whichports-ingest.service"]
