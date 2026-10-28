# The Debian-family clean box.
#
# ubuntu:26.04 ships with no curl, no gpg and no systemd, so the published
# one-liner cannot even start on it. This image adds the things a real Ubuntu
# server has and nothing else: curl to fetch the script, gnupg because the
# installer needs it to check the signing key, ca-certificates for the https
# fetch, systemd so the timer assertions are made against the real init rather
# than a stub, and ufw because Ubuntu Server ships it and its stock 640
# user.rules is what the non-root collection assertion reads its honest
# permission_denied from (docs/RECORD.md 4.72) until the installer's read
# grant, since record 4.176. sudo is added because the install command runs the
# agent through it and a real Ubuntu server has it (record 4.220). acl is not
# added here on purpose: the package depends on it and the install has to
# bring it. No whichports anything is baked in, and everything under test
# arrives through the installer.
FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd curl gnupg ca-certificates ufw sudo \
 && rm -rf /var/lib/apt/lists/*
# systemd's own shutdown signal, so `docker stop` is a clean shutdown.
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
