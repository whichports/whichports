#!/bin/sh
# Remove the agent and everything installing it put on this host.
#
#     sudo whichports-uninstall
#
# Why this exists. Measured on a clean box on 2026-08-16 and recorded in
# docs/PRODUCT.md 4f: after `apt-get purge` or `dnf remove` the binary and both
# units are gone and the timer is torn down, and four things stay. The
# enrolment file with the host credential, the state directory with the last
# document, the package source the installer wrote, and the signing key next to
# it. Three of those the installer created and no package manager can be
# expected to remove them. The credential is the one that matters, because an
# operator who purges the package reasonably believes we are gone.
#
# **Removing the credential file is not revocation.** The credential is ours
# rather than theirs (SI-5) and revoking the host from the dashboard is the
# whole revocation story. A file left on disk is a secret, not an access path,
# and a file deleted from disk is not a revoked host. This script says so at the
# end rather than letting anyone infer otherwise.
#
# Order matters. The package is removed last, because this script ships inside
# it, and a shell reading its own script incrementally should not have the file
# pulled out from under it halfway down.
set -eu

CONF_DIR="/etc/whichports"
STATE_DIR="/var/lib/whichports"
APT_LIST="/etc/apt/sources.list.d/whichports.list"
APT_UNATTENDED="/etc/apt/apt.conf.d/51whichports"
APT_KEYRING="/usr/share/keyrings/whichports.gpg"
RPM_REPO="/etc/yum.repos.d/whichports.repo"
RPM_KEY="/etc/pki/rpm-gpg/RPM-GPG-KEY-whichports"
DROPIN_DIR="/etc/systemd/system/whichports-agent.service.d"

# Our signing key as rpm names it in its own keyring, where dnf put it the
# first time it verified our package. No package owns it there and removing
# $RPM_KEY does not take it out. It is install.sh's KEY_FPR in lower case,
# and a test holds the two files together. rpm before 6 names a key by the
# last eight characters of its fingerprint and rpm 6 by the whole of it
# (measured 2026-10-03 in containers: the short name on rpm 4.14, 4.16, 4.19
# and 4.20, the long one on rpm 6.0. docs/RECORD.md 4.335 has the exact
# versions and distributions).
KEY_ID_LONG="3eedc9c6e4940a815d42ce43680a90826e2c982d"
KEY_ID_SHORT="6e2c982d"

# Whether a package database on this host still holds the package, and what
# it holds, as one line. Asked of dpkg and of rpm, whichever is here, after
# the removal. The package manager's exit code is never taken for the answer:
# until 2026-10-03 this script said "Removed" on a host with neither apt-get,
# dnf nor yum, where the package was still installed (openSUSE Leap 16.0,
# measured), and it said the same whenever a removal failed.
#
# Defined up here because a shell reads its script as it goes, and by the
# time this is called the package has taken this file with it.
package_left() {
  if command -v dpkg-query >/dev/null 2>&1; then
    status="$(dpkg-query -W -f='${Status}' whichports-agent 2>/dev/null)" || status=""
    case "$status" in
      ""|*not-installed) ;;
      *) echo "dpkg: whichports-agent, $status"; return 0 ;;
    esac
  fi
  if command -v rpm >/dev/null 2>&1; then
    if held="$(rpm -q whichports-agent 2>/dev/null)"; then
      echo "rpm: $held"
      return 0
    fi
  fi
  return 1
}

ASSUME_YES=no
for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=yes ;;
    -h|--help)
      echo "usage: whichports-uninstall [--yes]"
      echo "Removes the agent, its enrolment, its state, and the package source."
      exit 0 ;;
    *) echo "whichports-uninstall: unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "whichports-uninstall: run this as root." >&2
  exit 1
fi

# uname -n and not hostname: the openSUSE Leap 16.0 image has no hostname
# command, so this line read "hostname: command not found" there (seen
# 2026-10-03). uname answered on every distribution this script was run on.
echo "This will remove from $(uname -n):"
echo "  the whichports-agent package, its service and its timer"
echo "  $CONF_DIR, which holds this host's enrolment credential"
echo "  $STATE_DIR, which holds the last collected document"
echo "  the whichports package source and signing key"
echo "  the unattended-upgrades allowance for the whichports repository"
echo "  any file grant or drop-in the agent user was given"
echo "It leaves the whichports-agent system user and group, and says why at the end."
echo
if [ "$ASSUME_YES" != yes ]; then
  printf "Continue? [y/N] "
  read -r answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *) echo "Nothing was changed."; exit 1 ;;
  esac
fi

# 1. Stop it reporting before anything else, so nothing runs mid-removal.
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now whichports-agent.timer >/dev/null 2>&1 || true
  systemctl stop whichports-agent.service >/dev/null 2>&1 || true
fi

# Where this host reported to, read from its enrolment before that goes, so
# the last line names the dashboard the server is in. It named ours on every
# host, also on a server enrolled to a self-hosted instance (the second big
# test, 2026-10-25, case B12). Read with the shell alone, and kept only when
# it is a web address made of the characters such an address has.
DASHBOARD=""
if [ -r "$CONF_DIR/agent.conf" ]; then
  while IFS=' ' read -r key value || [ -n "$key" ]; do
    if [ "$key" = "server" ]; then
      DASHBOARD="$value"
      break
    fi
  done < "$CONF_DIR/agent.conf"
fi
case "$DASHBOARD" in
  http://?*|https://?*) ;;
  *) DASHBOARD="" ;;
esac
case "$DASHBOARD" in
  *[!A-Za-z0-9.:/_-]*) DASHBOARD="" ;;
esac

# 2. The files the installer wrote, which no package manager owns. Each is
#    removed by exact path: nothing here globs, and nothing recurses outside
#    the two directories this product created.
rm -f "$APT_LIST" "$APT_KEYRING" "$RPM_REPO" "$RPM_KEY" "$APT_UNATTENDED"
rm -rf "$CONF_DIR" "$STATE_DIR"

# 2b. The read grants the installer applies on ufw's and firewalld's files,
#     the runtime grants README.md documents by hand, and the drop-in an
#     installer before 0.1.10 could write, when this host has any of them.
#     The package's post-remove does
#     the same on a plain removal, and it is repeated here because this
#     script's promise is everything, standalone, whatever state the package
#     records are in. Removing an ACL entry that is not
#     there is not an error (setfacl(1)), a path this host does not have
#     just complains into the redirect, and the drop-in directory gets rmdir
#     rather than rm -rf because an operator's own drop-ins may live next to
#     ours and are not ours to delete. The one glob below feeds setfacl,
#     which takes an entry off a file and deletes nothing.
rm -f "$DROPIN_DIR/full-visibility.conf"
rmdir "$DROPIN_DIR" 2>/dev/null || true
if command -v setfacl >/dev/null 2>&1; then
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

# 2c. Our signing key in rpm's own keyring. Only a key whose name carries our
#     fingerprint is touched, and every other key on the host is left alone.
#     rpmkeys --delete took the key out on rpm 4.19, 4.20 and 6.0, and rpm 6
#     calls rpm -e on a key deprecated. rpm 4.14 and 4.16 have no such option
#     and take rpm -e (measured in the same containers as above). Whether the
#     key went is asked of rpm afterwards, the same way as for the package.
KEY_LEFT=""
if command -v rpm >/dev/null 2>&1; then
  for key in $(rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' 2>/dev/null); do
    case "$key" in
      "gpg-pubkey-$KEY_ID_SHORT-"*|"gpg-pubkey-$KEY_ID_LONG-"*)
        key_version="${key#gpg-pubkey-}"
        key_version="${key_version%-*}"
        if command -v rpmkeys >/dev/null 2>&1; then
          rpmkeys --delete "$key_version" >/dev/null 2>&1 || true
        fi
        if rpm -q "$key" >/dev/null 2>&1; then
          rpm -e "$key" >/dev/null 2>&1 || true
        fi
        if rpm -q "$key" >/dev/null 2>&1; then
          KEY_LEFT="$key"
        fi
        ;;
    esac
  done
fi

# 3. The package, last, for the reason at the top of this file. What the
#    package manager says is kept, and shown only if the package is still
#    there afterwards. rpm with neither dnf nor yum is what openSUSE Leap
#    16.0 has, and rpm removes a package it holds whatever installed it.
PACKAGE_MANAGER_SAID=""
if command -v apt-get >/dev/null 2>&1; then
  PACKAGE_MANAGER_SAID="$(apt-get purge -y whichports-agent 2>&1)" || true
elif command -v dnf >/dev/null 2>&1; then
  PACKAGE_MANAGER_SAID="$(dnf remove -y whichports-agent 2>&1)" || true
elif command -v yum >/dev/null 2>&1; then
  PACKAGE_MANAGER_SAID="$(yum remove -y whichports-agent 2>&1)" || true
elif command -v rpm >/dev/null 2>&1; then
  PACKAGE_MANAGER_SAID="$(rpm -e whichports-agent 2>&1)" || true
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

# "Removed" is said only when it is true. Anything this script promised and
# could not take away is named, and the exit status says so too.
PACKAGE_LEFT="$(package_left)" || PACKAGE_LEFT=""
NOT_FINISHED=no
echo
if [ -n "$PACKAGE_LEFT" ]; then
  NOT_FINISHED=yes
  echo "Not finished. The whichports-agent package is still installed:"
  echo "  $PACKAGE_LEFT"
  if [ -n "$PACKAGE_MANAGER_SAID" ]; then
    echo "The package manager said:"
    echo "$PACKAGE_MANAGER_SAID"
  fi
  echo "Its enrolment is gone from this machine, so the agent cannot report."
  echo "Run this again, or remove the package with your package manager."
fi
if [ -n "$KEY_LEFT" ]; then
  NOT_FINISHED=yes
  echo "Not finished. The whichports signing key is still in rpm's keyring:"
  echo "  $KEY_LEFT"
fi
if [ "$NOT_FINISHED" = no ]; then
  echo "Removed. This host no longer reports."
fi
echo
echo "Two things stay, on purpose."
echo
echo "The system user and group whichports-agent are still in /etc/passwd and"
echo "/etc/group. A removed package leaves its user so the id is never handed"
echo "to something else while files or backups still carry it, which is what"
echo "both distribution families ask of a package. It is a locked account"
echo "with no shell and no home. If you want it gone as well, check nothing"
echo "still carries the id, then remove it:"
echo "  find / -xdev \\( -user whichports-agent -o -group whichports-agent \\) 2>/dev/null"
echo "  userdel whichports-agent && groupdel whichports-agent 2>/dev/null"
echo
echo "And the host is not revoked. The credential is gone from this machine,"
echo "and that is not the same as revoked. Remove the server in the dashboard"
if [ -n "$DASHBOARD" ]; then
  echo "so the credential cannot be used from anywhere else, at"
  echo "$DASHBOARD"
else
  echo "so the credential cannot be used from anywhere else."
fi

if [ "$NOT_FINISHED" = yes ]; then
  exit 1
fi
