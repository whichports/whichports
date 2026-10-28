#!/bin/sh
# whichports agent installer, served at https://get.whichports.com:
#
#   curl -fsSL https://get.whichports.com | sh
#
# It configures the signed whichports package repository for your package
# manager and installs whichports-agent through it, so YOUR package manager
# verifies every byte against the published key before anything lands on
# disk. Run like that, with no arguments, nothing here starts a service: the
# timer stays off until you enable it, and the agent's stdout mode sends
# nothing off the machine.
#
# The dashboard's Add server window hands out the same line with the
# enrolment after it, and then it also connects the server:
#
#   curl -fsSL https://get.whichports.com | sh -s -- enroll --server=... --credential=...
#
# If you would rather not pipe a script into sh (a reasonable position), the
# repository setup below is short enough to do by hand; every step is plain
# to read here.
set -eu

BASE="https://get.whichports.com"
KEY_URL="$BASE/whichports-signing-public.asc"

# The fingerprint of the only key that may sign whichports packages. It is
# published in agent/packaging/signing/README.md and on the page, so you can
# compare it against this line before running anything. If the key served
# above does not match, this script stops and installs nothing.
#
# Be clear about what this does and does not buy. It catches a swapped key. It
# does not save you from a fully compromised get.whichports.com, because the
# same server hands you this script, and whoever changed the key could change
# this line too. The protection that survives that is below: the key is
# written to local disk once and both package managers are pointed at the
# local copy, so a later key rotation by an attacker is rejected rather than
# imported.
KEY_FPR="3EEDC9C6E4940A815D42CE43680A90826E2C982D"

KEYRING_DEB="/usr/share/keyrings/whichports.gpg"
APT_UNATTENDED="/etc/apt/apt.conf.d/51whichports"
KEYRING_RPM="/etc/pki/rpm-gpg/RPM-GPG-KEY-whichports"

# Everything that does something is inside main, and main is called on the
# last line of this file, inside braces. The script arrives through a pipe,
# and a shell runs a piped script as it reads it, so a download that stops
# halfway would otherwise run the half that arrived. A function is not run
# until it is called, and a brace group is not run until its closing brace
# has been read, so a script cut off at any byte runs nothing.
#
# The body keeps its indentation from before it was a function, because the
# two here-documents in it end on a word at the start of a line.
main() {

# Two ways to call this, and nothing else is accepted.
#
#   no arguments                install the agent and stop
#   enroll --server=... --credential=...
#                               install it, then connect this server: enrol
#                               with those values, turn the timer on, and
#                               collect once so the first report leaves now
#
# The second is what the dashboard's Add server window hands out. Until 0.1.12
# the window chained the enrolment after the pipe with &&, and a pipe's exit
# status is the shell's, which is 0 when nothing arrived: a failed download
# carried on to "sudo: whichports-agent: command not found" (docs/RECORD.md
# 4.228). As arguments there is nothing after the pipe to carry on to.
#
# Every argument is checked before anything is fetched or installed. Until
# 0.1.10 one flag, --full-visibility, widened the unit to four capabilities;
# an old command that still carries it stops here rather than installing
# something narrower than it asked for.
# credential_ok answers whether its argument has the shape of a credential
# the dashboard hands out: whp_, then 32 or more of letters, digits, - and _,
# and no more than 128 characters in all. It is the agent's own rule
# (ValidateCredential in internal/report), repeated here so that a credential
# copied wrongly stops this script before it fetches or installs anything,
# and a test holds the two to the same answers. The value is never printed.
credential_ok() {
  # In the C locale a range like a-z is the ASCII letters and nothing else.
  # The parentheses keep that setting to this one check.
  (
    LC_ALL=C
    case "$1" in whp_*) ;; *) exit 1 ;; esac
    body="${1#whp_}"
    case "$body" in *[!0-9A-Za-z_-]*) exit 1 ;; esac
    [ "${#body}" -ge 32 ] && [ "${#1}" -le 128 ]
  )
}

# install_with_dnf installs the agent with dnf, reading our repository alone
# when it can.
#
# dnf reads the metadata of every enabled repository before it installs
# anything, and stops when one cannot be read. A stalled Rocky 8 mirror held
# an install over ten minutes twice on 2026-09-30 while everything the
# package needed was installed (docs/RECORD.md 4.220). In a plain
# rockylinux:8 container one enabled repository that never answered failed
# the install after 142 seconds, ours never asked (docs/RECORD.md 4.460).
#
# The package needs shadow-utils and acl and nothing else (packaging/nfpm.yaml,
# and the published package's rpm --requires, read 2026-10-14). When rpm
# says both are installed, ours is the only repository the install needs,
# and every other one is left unread. dnf's manual calls --repo "basically a
# shortcut for --disablerepo="*" --enablerepo=<repoid>", and the pair itself
# is used. Rocky Linux 8's dnf 4.7.0, AlmaLinux 9's 4.14.0, AlmaLinux 10's
# 4.20.0 and Fedora 42's dnf5 each list it in their own --help, and each
# enabled ours alone with it (2026-10-14, docs/RECORD.md 4.460). When
# either dependency is missing it comes from the distribution's
# repositories, so dnf reads every repository, as before.
#
# These options choose which repositories are read. They change nothing in
# how a package is verified: the repository file above keeps gpgcheck,
# repo_gpgcheck and the local key.
#
# WHICHPORTS_INSTALLER_CONNECTS tells the package whether this installer
# connects the server right after it, so the package's own closing lines do
# not tell the reader to do what the next lines do (docs/RECORD.md 4.184).
install_with_dnf() {
  if rpm -q --whatprovides shadow-utils acl >/dev/null 2>&1; then
    echo "* installing whichports-agent from its own repository, shadow-utils and acl are installed"
    WHICHPORTS_INSTALLER_CONNECTS="$ENROLL" dnf install -y --disablerepo='*' --enablerepo=whichports whichports-agent
  else
    echo "* installing whichports-agent, reading every repository: shadow-utils or acl has to be downloaded"
    WHICHPORTS_INSTALLER_CONNECTS="$ENROLL" dnf install -y whichports-agent
  fi
}

ENROLL=no
if [ "$#" -gt 0 ]; then
  if [ "$1" != "enroll" ]; then
    echo "unknown argument: $1 (this installer takes no arguments, or: enroll --server=... --credential=...)" >&2
    exit 2
  fi
  shift
  ENROLL=yes
  HAS_SERVER=no
  HAS_CREDENTIAL=no
  for arg in "$@"; do
    case "$arg" in
      --server=?*) HAS_SERVER=yes ;;
      --credential=?*)
        if ! credential_ok "${arg#--credential=}"; then
          echo "the credential is not one the dashboard hands out. Copy the command exactly as the Add server window shows it." >&2
          exit 2
        fi
        HAS_CREDENTIAL=yes ;;
      --prober-server=?*|--prober-proof-key=?*) ;;
      *)
        echo "unknown argument: $arg (enroll takes --server=, --credential=, --prober-server= and --prober-proof-key=)" >&2
        exit 2 ;;
    esac
  done
  if [ "$HAS_SERVER" != yes ] || [ "$HAS_CREDENTIAL" != yes ]; then
    echo "enroll needs both --server= and --credential=, the Add server window shows the exact command" >&2
    exit 2
  fi
fi

[ "$(id -u)" = "0" ] || { echo "run as root (the package install needs it)" >&2; exit 1; }
# Our repository publishes the agent for x86_64 alone (packaging/nfpm.yaml),
# so on any other machine apt or dnf would find no package after the
# repository was written. Refused here, before anything is fetched or written,
# and before the gpg check, so nobody installs gnupg for nothing.
ARCH="$(uname -m)"
[ "$ARCH" = "x86_64" ] || { echo "this machine is $ARCH, and the agent is published for x86_64 only. Nothing was installed." >&2; exit 1; }
command -v gpg >/dev/null 2>&1 || { echo "gpg not found: install gnupg first" >&2; exit 1; }

# Fetch the key once, check it is the key we published, and keep it. Every
# later verification uses this local file.
KEY_TMP="$(mktemp)"
trap 'rm -f "$KEY_TMP"' EXIT INT TERM
curl -fsSL "$KEY_URL" -o "$KEY_TMP"
GOT_FPR="$(gpg --with-colons --show-keys "$KEY_TMP" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')"
if [ "$GOT_FPR" != "$KEY_FPR" ]; then
  echo "signing key fingerprint mismatch, installing nothing." >&2
  echo "  expected: $KEY_FPR" >&2
  echo "  served:   ${GOT_FPR:-none}" >&2
  exit 1
fi
echo "* signing key verified: $KEY_FPR"

if command -v apt-get >/dev/null 2>&1; then
  echo "* configuring the apt repository"
  # signed-by pins this repo to exactly our key, nothing system-wide, and to
  # the copy on this disk rather than to anything fetched later.
  gpg --dearmor < "$KEY_TMP" > "$KEYRING_DEB"
  chmod 0644 "$KEYRING_DEB"
  echo "deb [signed-by=$KEYRING_DEB] $BASE/deb stable main" \
    > /etc/apt/sources.list.d/whichports.list
  apt-get update -o Dir::Etc::sourcelist=sources.list.d/whichports.list \
                 -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
  # acl is a dependency (packaging/nfpm.yaml) and it comes from the
  # distribution's archive, not from ours. The update above refreshed our list
  # only, so on a box whose distribution lists are empty apt cannot find acl and
  # refuses the whole install. The clean-box Ubuntu image is such a box, and
  # that refusal went unseen from 2026-09-13 to 2026-09-29. So every list is
  # refreshed, but only while acl still has to be downloaded: a host that
  # already has it installs exactly as before.
  if ! dpkg-query -W -f='${Status}' acl 2>/dev/null | grep -q "install ok installed"; then
    echo "* refreshing the distribution's package lists, acl has to be downloaded"
    apt-get update
  fi
  # Let unattended-upgrades upgrade the agent. Ubuntu's default allow-list in
  # 50unattended-upgrades is the distribution's own pockets and nothing else,
  # and this repository publishes Origin "whichports", Suite "stable"
  # (packaging/repo/build-repo.sh), so without this line the agent is never
  # upgraded by the machine on its own. The owner, 2026-09-10: on by default,
  # because nobody opts in to upgrades. uninstall.sh removes the file.
  echo "* allowing unattended-upgrades to upgrade whichports-agent"
  cat > "$APT_UNATTENDED" <<APTCONF
// Written by the whichports installer. Lets unattended-upgrades install new
// versions of whichports-agent from get.whichports.com. Remove this file to
// keep the agent at the version you chose.
Unattended-Upgrade::Allowed-Origins {
    "whichports:stable";
};
APTCONF
  chmod 0644 "$APT_UNATTENDED"
  echo "* installing whichports-agent"
  # WHICHPORTS_INSTALLER_CONNECTS: see install_with_dnf above.
  WHICHPORTS_INSTALLER_CONNECTS="$ENROLL" apt-get install -y whichports-agent
elif command -v dnf >/dev/null 2>&1; then
  echo "* configuring the dnf repository"
  # gpgkey points at the local file, not at a URL, and this is the important
  # part. dnf documents gpgkey as: "If a file can not be verified using the
  # already imported keys, import of keys from this option is attempted and
  # the keys are then used for verification." With a URL there, a later
  # compromise of get.whichports.com could serve a new key alongside packages
  # signed by it, and dnf would fetch that key and accept them. Pointing at a
  # file on this disk removes the re-fetch, which is the same posture apt's
  # signed-by gives on the other branch.
  mkdir -p "$(dirname "$KEYRING_RPM")"
  cp "$KEY_TMP" "$KEYRING_RPM"
  chmod 0644 "$KEYRING_RPM"
  cat > /etc/yum.repos.d/whichports.repo <<EOF
[whichports]
name=whichports
baseurl=$BASE/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file://$KEYRING_RPM
EOF
  install_with_dnf
  # dnf has no per-repository allow-list. dnf-automatic upgrades everything
  # from every enabled repository once it is on, which is a whole-system
  # choice and not this installer's to make, so it is said here rather than
  # done.
  echo "to let this host upgrade the agent on its own:"
  echo "  dnf install -y dnf-automatic && systemctl enable --now dnf-automatic-install.timer"
else
  # Neither apt nor dnf, which is openSUSE among others. It is not supported
  # for now, by decision (docs/RECORD.md 4.339), and this says so. Until
  # 2026-10-03 it named two addresses to take a package from by hand, and
  # both answered 404, so the one thing it told a person to do could not be
  # done. The first sentence is kept as it was: the docs page quotes it, and
  # a test holds the page to this file.
  echo "no apt or dnf found. This system is not supported, and nothing was installed." >&2
  exit 1
fi

# The read grants, applied by default since 0.1.10 (docs/RECORD.md 4.176:
# the firewall's rules are the core of the product). ufw keeps
# its compiled rules 640 root and firewalld its directory 750 root, and the
# declared side of the Rules tab is read from those files, so without a grant
# a fresh host reads "not readable" there. Each grant is one read-only ACL
# entry the operator can see with getfacl and take back with setfacl -x, and
# whichports-uninstall takes them all back. Read and never write: r on a
# file, rx on a directory because entering one needs x. Applied only where
# the target exists, since ufw and firewalld are each optional, and
# re-running converges because setfacl -m replaces an entry that is already
# there. setfacl comes from the acl package, which the agent package depends
# on. The Docker group and the Podman socket are write access to a runtime
# and stay the operator's own lines in README.md.
#
# setfacl follows a symlink argument (setfacl(1)), so a link is never handed
# to it unchecked.
#
# One shape of link is a distribution's own and is granted through. firewalld
# on Fedora 44 ships /etc/firewalld/firewalld.conf as a link to
# firewalld-standard.conf beside it, both owned by the package
# (firewalld-2.4.4-1.fc44, read 2026-10-02). Until 0.1.12 this function
# refused every link and stopped, so stock Fedora with firewalld could not
# install, and the refusal advised removing firewalld's own file
# (docs/RECORD.md 4.223).
#
# So a link to a regular file in the link's own directory is followed, and the
# grant is put on the file it resolves to, by that file's name, so that what
# was checked is what is granted. Every other link still stops the run: one
# that leaves its directory, one that names a directory, one that names
# nothing. Such a link means someone rearranged the host, and that is theirs
# to look at, not this script's to reach through.
grant() {
  perms="$1"
  shift
  for path in "$@"; do
    target="$path"
    if [ -L "$path" ]; then
      # readlink -f follows every link on the way and prints where the name
      # ends up. Both directories are compared in that resolved form, so a
      # host whose /etc is itself reached through a link compares equal.
      target="$(readlink -f "$path" 2>/dev/null || true)"
      here="$(readlink -f "$(dirname "$path")" 2>/dev/null || true)"
      if [ -z "$target" ] || [ -z "$here" ] || [ ! -f "$target" ] \
         || [ "$(dirname "$target")" != "$here" ]; then
        echo "refusing: $path is a symlink, and not to a file beside it." >&2
        echo "  it points at: ${target:-nothing that resolves}" >&2
        echo "  Nothing was granted on it. Look at why the link is there, then rerun the installer." >&2
        exit 1
      fi
    fi
    setfacl -m "u:whichports-agent:$perms" "$target"
    if [ "$target" = "$path" ]; then
      echo "  readable:   $path"
    else
      echo "  readable:   $path (a link to $target)"
    fi
  done
}
if [ -f /etc/ufw/user.rules ]; then
  grant r /etc/ufw/user.rules
fi
if [ -f /etc/ufw/user6.rules ]; then
  grant r /etc/ufw/user6.rules
fi
if [ -d /etc/firewalld ]; then
  grant rx /etc/firewalld
  if [ -d /etc/firewalld/zones ]; then
    grant rx /etc/firewalld/zones
  fi
  if [ -f /etc/firewalld/firewalld.conf ]; then
    grant r /etc/firewalld/firewalld.conf
  fi
  for zone in /etc/firewalld/zones/*.xml; do
    if [ -f "$zone" ]; then
      grant r "$zone"
    fi
  done
fi

if [ "$ENROLL" = yes ]; then
  # The three things the Add server window used to chain after the pipe, in
  # the same order. The agent is called by its full path because this script
  # runs under sudo, whose own PATH is the distribution's to set. Under
  # set -e a step that fails stops here, so a server that could not enrol
  # never gets its timer turned on.
  echo
  echo "* connecting this server"
  # The agent is in /usr/bin from 0.1.12. Where the package manager kept an
  # older one, held back or from another source, it is in /usr/local/bin and
  # the line below would end in the shell's own "No such file or directory".
  if [ ! -x /usr/bin/whichports-agent ]; then
    echo "the whichports-agent package on this server is older than 0.1.12, so this installer cannot connect it." >&2
    echo "  Upgrade the package, then run this line again." >&2
    exit 1
  fi
  /usr/bin/whichports-agent enroll "$@"
  systemctl enable --now whichports-agent.timer
  # One collection at once. The timer fires on the quarter hour with up to
  # two minutes of delay, so without this a working install says nothing for
  # up to seventeen minutes (docs/RECORD.md 4.184, 4.187). The unit is a
  # oneshot, so starting it fails when the collection or its delivery fails,
  # and that is said in plain words rather than left to systemd's own line.
  if ! systemctl start whichports-agent.service; then
    echo "the first report did not go out. The timer is on and tries again within 15 minutes." >&2
    echo "  why:  journalctl -u whichports-agent.service -n 20" >&2
    exit 1
  fi
  echo
  echo "installed and connected. This server reports every 15 minutes."
  echo "  look:       whichports-agent --mode=stdout"
  echo "  document:   /var/lib/whichports/host.json"
else
  echo
  echo "installed. Next steps:"
  echo "  one shot:   whichports-agent --mode=stdout"
  # Run again on a server whose timer is on, this said to turn it on, under
  # the package's own line saying it was on already. So the timer is read
  # here as the package reads it, which asks systemd and starts nothing.
  if command -v systemctl >/dev/null 2>&1 \
     && systemctl is-enabled whichports-agent.timer >/dev/null 2>&1; then
    echo "  timer:      already on, and left as it was"
  else
    echo "  every 15m:  systemctl enable --now whichports-agent.timer"
  fi
  echo "  document:   /var/lib/whichports/host.json"
fi

}

# The call, inside braces for the reason given above main: cut this line
# short anywhere and the shell has an unfinished group and runs nothing.
{ main "$@"; }
