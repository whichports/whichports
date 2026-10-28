# Test-only images for the prober API's end to end run (selfhost/e2e/run.py).
# Nothing here is part of what a self-hosted instance runs.
#
# Three images. `ours` is the product's control plane image with an ssh client
# added, because our side drives the vantage over ssh as the production box
# does. `vantage` is a prober box: sshd and the six modules a real one
# gets, nothing else. `target` is a server somebody
# watches: the agent, its user and directories as the package's postinstall
# makes them, and two listening ports.
#
# The openssh packages come from Debian's archive at build time and are not
# pinned beyond the base image's release. That is accepted for a test rig and
# would not be for an image a tester runs.
#
# The vantage's user gets `*` as its password field: no password can match
# it, and unlike the `!` useradd leaves, sshd does not read it as a locked
# account and refuse the key.
#
# No key is baked in. The vantage makes its host keys when it starts, and the
# driver makes the ssh key and every credential per run.

# ------------------------------------------------------------------- ours
FROM whichports-controlplane:local AS ours
USER root
# ssh reads ~/.ssh from the home directory in the user database, not from
# $HOME, so the product image's user gets a home here that it lacks there.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && usermod --home /e2e/home whichports \
    && install -d -o whichports -g whichports -m 0700 /e2e/home /e2e/home/.ssh
USER whichports

# ---------------------------------------------------------------- vantage
FROM python:3.12.14-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS vantage
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/ssh/ssh_host_* \
    && useradd --uid 10001 --create-home --shell /bin/sh prober \
    && usermod -p '*' prober \
    && install -d -o prober -g prober -m 0700 /home/prober/.ssh \
    && install -d -m 0755 /run/sshd /opt/whichports/app \
    && touch /opt/whichports/app/__init__.py
# The closed set, VANTAGE_MODULES in controlplane/app/probe_runner.py.
# selfhost/test_static.py holds this line and that list equal.
COPY controlplane/app/prober.py controlplane/app/authz.py controlplane/app/ratelimit.py controlplane/app/dnstxt.py controlplane/app/probe_runner.py controlplane/app/workspace.py /opt/whichports/app/
COPY selfhost/e2e/sshd.conf /etc/ssh/sshd_config.d/e2e.conf
COPY selfhost/e2e/vantage.py /e2e/vantage.py
CMD ["python3", "/e2e/vantage.py"]

# ----------------------------------------------------------------- target
FROM python:3.12.14-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS target
# What agent/packaging/scripts/postinstall.sh makes: the user, the state
# directory it writes, and the directory `enroll` writes the config into.
RUN groupadd --system whichports-agent \
    && useradd --system --gid whichports-agent --home-dir /var/lib/whichports \
        --no-create-home --shell /usr/sbin/nologin whichports-agent \
    && install -d -o whichports-agent -g whichports-agent -m 0750 /var/lib/whichports \
    && install -d -m 0755 /etc/whichports
# Built by the driver from agent/ for this machine's architecture.
COPY selfhost/e2e/build/whichports-agent /usr/local/bin/whichports-agent
COPY selfhost/e2e/listen.py /e2e/listen.py
CMD ["python3", "/e2e/listen.py"]
