#!/bin/sh
# Post-remove: reload systemd so the removed units vanish from its view, and
# on a real removal take back the read grants the installer applies, the
# runtime grants README.md documents by hand, and the drop-in an installer
# before 0.1.10 could write, if this host has any of them. The state
# directory with the last document is deliberately left
# behind: it is the operator's data, and purge semantics differ per package
# manager, so we take the conservative path for both.
#
# Like the pre-remove, this runs during upgrades too, as the OLD package's
# cleanup, and the two packagers signal that differently:
#
#   deb  passes "upgrade" as $1 when upgrading, "remove" on a real removal.
#   rpm  passes the number of versions that will remain afterwards: "1" on
#        an upgrade, "0" on the final erase.
#
# The widening is the operator's explicit choice exactly like the timer
# state, so an upgrade leaves it alone. docs/RECORD.md 4.48 is what a
# scriptlet that forgets which case it is in cost the last time.
set -e

reload() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
  fi
}

case "${1:-}" in
  upgrade|1)
    reload
    exit 0
    ;;
esac

# A real removal. The installer applies read grants on ufw's and firewalld's
# files, README.md documents the runtime grants by hand, an installer before
# 0.1.10 could write the drop-in, no package owns any of them, and an agent
# that is gone needs none of them. Every step is a no-op on a host that has
# none: rm -f ignores a
# missing file, setfacl documents that removing an absent entry is not an
# error (setfacl(1)), and the redirects swallow the complaint about a path
# this host does not have. The directory is taken down with rmdir rather
# than rm -rf, because an operator's own drop-ins may live next to ours and
# are not ours to delete.
rm -f /etc/systemd/system/whichports-agent.service.d/full-visibility.conf
rmdir /etc/systemd/system/whichports-agent.service.d 2>/dev/null || true

if command -v setfacl >/dev/null 2>&1; then
  # The exact targets install.sh grants on and README.md documents. An unmatched
  # zone glob passes through as a literal path and falls into the same
  # swallowed complaint as any other absent path.
  for path in \
    /etc/ufw/user.rules /etc/ufw/user6.rules \
    /etc/firewalld /etc/firewalld/zones /etc/firewalld/firewalld.conf \
    /etc/firewalld/zones/*.xml \
    /run/podman /run/podman/podman.sock; do
    setfacl -x u:whichports-agent "$path" 2>/dev/null || true
  done
fi
if command -v gpasswd >/dev/null 2>&1; then
  gpasswd -d whichports-agent docker >/dev/null 2>&1 || true
fi

reload
