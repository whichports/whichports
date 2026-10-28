#!/bin/sh
# Post-install: create the agent's own user, hand it the state directory,
# fix the enrolment file's ownership if one exists, and reload systemd so the
# shipped units are visible. The timer is deliberately NOT enabled here,
# because turning on a recurring job is the operator's decision, not the
# package's.
#
# The unit runs as whichports-agent with CAP_NET_ADMIN and CAP_NET_RAW, which
# docs/RECORD.md 4.72 measured as enough for every port, every bind address
# and every live kernel rule. This script owns the three facts on disk that
# make that work: the user exists, the state directory is writable by it, and
# the enrolment file is readable by it.
set -e

# Idempotent on purpose: this runs on every install AND every upgrade, on both
# families, so each step has to be safe to repeat.
if ! getent group whichports-agent >/dev/null; then
  groupadd --system whichports-agent
fi
if ! getent passwd whichports-agent >/dev/null; then
  useradd --system --gid whichports-agent \
    --home-dir /var/lib/whichports --no-create-home \
    --shell /usr/sbin/nologin \
    --comment "whichports host collection" whichports-agent
fi

# The state directory belongs to the agent user because timer mode writes the
# host document there. 0750 so nothing unprivileged reads the port list.
#
# Checked for a symlink first, here and again for the enrolment file below,
# because chown and chmod both follow a link to whatever it points at, so a
# link planted at either path would have this script, running as root, hand
# ownership of an arbitrary file to the agent user. Planting one already takes
# root, but writeFileAtomic in cmd/agent/main.go makes the argument in
# writing: "unreachable given the directory permissions" is a weaker thing to
# rely on than not following a link at all. Refusing loudly beats skipping
# quietly, because a link sitting here means someone rearranged the host, and
# that is the operator's to investigate, not this script's to work around.
if [ -L /var/lib/whichports ]; then
  echo "whichports-agent postinstall: /var/lib/whichports is a symlink." >&2
  echo "Refusing to change ownership through it. Remove the link and reinstall." >&2
  exit 1
fi
mkdir -p /var/lib/whichports
# --no-dereference so the chown itself can never cross a link either, even one
# that appears after the check above. chmod has no equivalent flag, so for the
# chmod the check is the guard.
chown --no-dereference whichports-agent:whichports-agent /var/lib/whichports
chmod 0750 /var/lib/whichports

# The enrolment file is not owned by the package (that is what lets it survive
# upgrades, docs/RECORD.md 4.48), so this is the only place that can fix its
# ownership on an upgrade from a root-era install, where it sits root:root
# 0600 and the agent user cannot read the credential. root keeps ownership,
# the group gets read, nobody else gets anything. A host that has not enrolled
# yet has no file, and that is the normal fresh install, not an error.
enrolled=no
# The -f test follows a link too, so without its own check a symlink here
# would pass as the enrolment file and the repair below would reach through it.
if [ -L /etc/whichports/agent.conf ]; then
  echo "whichports-agent postinstall: /etc/whichports/agent.conf is a symlink." >&2
  echo "Refusing to change ownership through it. Remove the link and reinstall." >&2
  exit 1
fi
if [ -f /etc/whichports/agent.conf ]; then
  chown --no-dereference root:whichports-agent /etc/whichports/agent.conf
  chmod 0640 /etc/whichports/agent.conf
  enrolled=yes
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

# Put /usr/local/bin back when the upgrade took it away.
#
# Until 0.1.12 the package shipped its two programs in /usr/local/bin, so it
# listed that directory as its own. Upgrading from such a version makes dpkg
# delete the directory when ours were the only files in it: measured on
# 2026-10-02 on Ubuntu 26.04.1 with dpkg 1.23.7, while rpm 4.19 on
# AlmaLinux 10.2 left it in place. The directory is the administrator's, and
# Debian Policy 9.1.2 says of it "You must not remove any of the directories
# listed in 4.9, even if you created them." So it is put back the way that
# section describes it: 0755 root:root, or 2775 root:staff on a machine that
# has /etc/staff-group-for-usr-local.
#
# Only when it is missing while /usr/local itself is there, so a machine that
# has the directory is never touched. And never fatal: the same section says
# /usr/local can be mounted read-only from another server, and a failed mkdir
# there is no reason to fail an install.
if [ -d /usr/local ] && [ ! -e /usr/local/bin ] && [ ! -L /usr/local/bin ]; then
  if mkdir /usr/local/bin 2>/dev/null; then
    if [ -e /etc/staff-group-for-usr-local ]; then
      chown root:staff /usr/local/bin 2>/dev/null || true
      chmod 2775 /usr/local/bin 2>/dev/null || true
    else
      chmod 0755 /usr/local/bin 2>/dev/null || true
    fi
  fi
fi

# What is left to do, rather than the same four lines every time.
#
# This runs on every install AND every upgrade, and it used to close by telling
# the operator to enrol and to enable the timer unconditionally. On an upgrade
# of a host that has been reporting for months that is two instructions it has
# already followed, printed under a package it did not choose to be told about
# (the owner, 2026-08-22, reading the output of a fleet upgrade).
#
# The two facts are read off the disk rather than inferred from which packager
# is calling and with what argument. deb and rpm signal install-versus-upgrade
# differently and neither of them answers the question actually being asked,
# which is not "is this an upgrade" but "does this host still need connecting,
# and is its timer on". A reinstall over a working enrolment is an install by
# the packager's reckoning and needs no enrol line either.
timer_on=no
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-enabled whichports-agent.timer >/dev/null 2>&1; then
    timer_on=yes
  fi
fi

echo "whichports-agent installed."
echo "  look first: whichports-agent --mode=stdout   (prints the document, sends nothing off this machine)"
echo "  document:   /var/lib/whichports/host.json"
# The installer run with enroll connects this server right after the package:
# it enrols, turns the timer on and collects once, then says so in its own
# last lines. It sets WHICHPORTS_INSTALLER_CONNECTS=yes for the package
# manager, which hands its environment on to this script, so the two lines
# below do not tell the reader to do what the next lines do (docs/RECORD.md
# 4.184, 4.460). Anyone else, an install by hand included, gets them.
if [ "${WHICHPORTS_INSTALLER_CONNECTS:-}" != yes ]; then
  if [ "$timer_on" = yes ]; then
    echo "  timer:      already enabled, and this left it alone"
  else
    echo "  every 15m:  systemctl enable --now whichports-agent.timer"
  fi
  if [ "$enrolled" = yes ]; then
    echo "  connected:  enrolled already, so reporting carries on"
  else
    echo "  connect:    whichports-agent enroll --server=... --credential=...   (from the dashboard's add-host screen; without it the timer stays local-only)"
  fi
fi
