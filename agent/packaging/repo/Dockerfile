# Repo-builder image: the Linux tools that generate apt + rpm repository
# metadata. It carries NO key; `make repo` mounts the signing key read-only
# at run time into an ephemeral keyring (build-repo.sh). Used only on the
# maintainer's machine, never on any server.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      apt-utils \
      dpkg-dev \
      createrepo-c \
      rpm \
      gpg \
      gnupg \
      gzip \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Build context is packaging/ (make repo passes -f packaging/repo/Dockerfile
# packaging), so both the builder script and the installer are reachable.
COPY repo/build-repo.sh /usr/local/bin/build-repo.sh
COPY install.sh /usr/local/share/whichports/install.sh
RUN chmod 0755 /usr/local/bin/build-repo.sh

ENTRYPOINT ["/usr/local/bin/build-repo.sh"]
