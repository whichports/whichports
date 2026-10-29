#!/bin/sh
# whichports, the self-hosted install. Served as
# https://get.whichports.com/selfhost.sh and run on the server that will hold
# the instance:
#
#   curl --proto '=https' --tlsv1.2 -fsSL https://get.whichports.com/selfhost.sh | sudo sh
#
# --proto '=https' keeps curl on https, a redirect included, and --tlsv1.2
# refuses an older TLS.
#
# It does what selfhost/README.md does by hand under "By hand", and says what
# it will do before it does any of it. It asks three things at the terminal:
# the domain, an email address and a password. Every answer is checked
# before anything on the server is changed. Then it clones the repository
# into /opt/whichports, writes selfhost/.env there readable by root alone,
# builds and starts the stack, waits until the control plane reads healthy,
# and makes the account.
#
# Then it asks our probers for this server (docs/SPEC-open-beta.md). It
# sends our API the address and a claim, 32 random bytes it keeps in
# selfhost/.prober-claim readable by root alone, and our API mails that
# address eight digits. The person types them here, and with the claim they
# bring back the invite line, which it checks, writes into .env, and starts
# the stack again with. Skipped, refused or unreachable, the install goes on
# without our probers, and running the line again asks again. Nothing else
# about the server goes: no domain, no host name. Our API sees the address
# each request comes from, as every server it is asked by.
#
# It runs as root, and builds and runs nothing but the one folder it makes:
# /opt/whichports, owned by root throughout and writable by nobody else, in
# which git sees nothing it does not know. A folder there that is anything
# else stops it before anything is changed. So no other user of the server
# decides what root builds and runs, with a file of theirs or an edit.
#
# Run again, it changes nothing it does not have to: its own folder is used
# as it is, an .env that holds exactly these answers is left as it is, and a
# second account is never made. An .env that holds anything else, edited by
# hand or written with other answers, stops it before anything is changed,
# and it says so.
#
# What it never does, and selfhost/test_install.py holds it to each:
#
#   - It runs no eval and no sh -c of a text it built. Every command is
#     written out here word by word (SI-4).
#   - The password is never on a command line, in the environment of a
#     command, in a file, or in anything printed. It is read with the
#     terminal's echo off and handed to the control plane on standard input
#     by printf, a builtin of dash and of bash, so no program is started with
#     it. The control plane keeps its hash and nothing else.
#   - The claim and the code are never on a command line or in the
#     environment of a command either: printf hands them to curl on its
#     standard input. So is the invite line's API key, the one time a run
#     sends it.
#   - Nothing it receives from our probers is run or evaluated. An invite
#     line is written into .env only when it has the line's shape and names
#     the host it called, written below as PROBERS. Anything else counts as
#     our probers not answering.
#   - It sends nothing before the yes, and the plan says what goes.
#   - It asks for no provider token and no SSH key (SI-5).
#   - It makes the account at this terminal, never through the page, so the
#     first person to open the dashboard cannot make it.
#
# WHICHPORTS_REPOSITORY clones from another address, a mirror or a test's
# repository on this machine. Unset, it is the public repository.
set -eu

REPOSITORY="https://github.com/whichports/whichports"

# The release this script installs: a tag of the repository, and the commit
# that tag names. The copy served at get.whichports.com has both filled in by
# selfhost/release_installer.py. The clone is of that tag, and git's own HEAD
# must be that commit or nothing is built, so a tag moved where the
# repository lives cannot change what root builds. In the repository both
# lines are empty, and a copy with them empty installs nothing.
RELEASE_TAG=
RELEASE_COMMIT=

# Where the instance lives. This script makes the folder, and builds and runs
# nothing from any other.
INSTALL_DIR=/opt/whichports

# The user this script runs as and who must own every file of that folder:
# root.
ROOT_UID=0

# Where the kernel lists the TCP sockets of this server, IPv4 and IPv6, read
# to see whether something else already listens on a port the stack needs.
PROC_NET=/proc/net

# The ports the stack listens on: Caddy's, and the control plane's on
# 127.0.0.1. env.example names both, and the one line changes neither.
PORTS="443 8410"

# How long the stack has to come up. The README measured the control plane
# reading healthy 22 and 45 seconds after its start on two Docker versions,
# so three minutes is a stack that is not coming up, and the person is told
# where to look.
WAIT_SECONDS=180

# How long every container has to stay up, unchanged, after Compose says the
# stack is up. compose up --wait has ended 0 while Caddy, with 443 held by
# another program, exited at once and restarted over and over (Compose
# 5.6.0, three runs in six, 2026-10-20). Docker waits longer between such
# restarts each time, so a container that does not stay up reads restarting,
# or has a higher restart count, ten seconds later.
STEADY_SECONDS=10

# How often one question is asked before the installer stops.
TRIES=3

# Our probers' API: the one host the signup calls, and the one host an
# invite line it writes may name.
PROBERS=app.whichports.com
SIGNUP_PATH=/api/v1/instance-signup
COLLECT_PATH=/api/v1/instance-signup/collect
DONE_PATH=/api/v1/instance-signup/done
VANTAGES_PATH=/api/v1/prober/vantages

# Every call to our probers ends in time: a firewall that drops packets would
# otherwise hold the install for as long as the connection's own timeouts.
CONNECT_SECONDS=10
CALL_SECONDS=20

# How many codes may be typed, as many as our API takes for one claim, and
# how long a claim lives there: a run inside that time asks for the code
# again and mails nothing new.
CODE_TRIES=5
CLAIM_MINUTES=1440

# Everything that does something is inside main, and main is called on the
# last line of this file, inside braces. Piped into sh, a script runs as it
# arrives, so a download cut off halfway would otherwise run the half that
# came. A function is not run until it is called, and a brace group not until
# its closing brace has been read, so a script cut off at any byte runs
# nothing. agent/packaging/install.sh does the same, for the same reason.
main() {
  changed=no
  # Files this script writes are writable by root alone, whatever the
  # umask of the shell that ran it.
  umask 022
  repository=${WHICHPORTS_REPOSITORY:-$REPOSITORY}
  # Echo back on if the person stops it while a password is being typed.
  trap 'stty echo </dev/tty 2>/dev/null; exit 130' INT TERM

  need_release
  need_root
  need_terminal
  check_tools
  find_install
  check_ports
  say_what_it_asks

  ask_domain
  ask_email
  ask_password
  find_probers
  say_the_plan_and_ask_to_go_on

  if [ "$clone" = yes ]; then
    clone_it
  fi
  write_env
  build_and_start
  make_account
  use_our_probers
  say_done
}

# ------------------------------------------------------------ saying things

# say prints its one argument and a newline. printf, not echo, because
# dash's echo reads a backslash in a path or in Docker's words as an escape.
say() {
  printf '%s\n' "$1"
}

stop() {
  say "$1" >&2
  if [ "$changed" = no ]; then
    say "Nothing was changed." >&2
    exit 2
  fi
  exit 1
}

refuse() {
  say "  $1" >&2
}

# quoted prints its argument as one word for a POSIX shell: in single quotes,
# with each single quote in it closed, escaped and opened again. A command
# this script prints for a person to paste as root carries a mail address
# or a path this way, so a quote or a $ in it stays a character.
quoted() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

need_release() {
  (
    LC_ALL=C
    case $RELEASE_TAG in ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*) exit 1 ;; esac
    case $RELEASE_COMMIT in *[!0-9a-f]*) exit 1 ;; esac
    [ "${#RELEASE_COMMIT}" -eq 40 ]
  ) || stop "This copy of the installer names no release, so it installs nothing. Run the line as the README gives it, which fetches the copy that does."
}

need_root() {
  if [ "$(id -u)" != "$ROOT_UID" ]; then
    stop "This installer runs as root, because it installs to $INSTALL_DIR and runs the stack from there. Run the line with sudo."
  fi
}

need_terminal() {
  # Piped into sh, standard input is this script, so the questions are asked
  # on the terminal itself.
  if ! (: </dev/tty) 2>/dev/null; then
    stop "This installer asks questions, so it needs a terminal. Run it in a terminal over ssh, or at the console."
  fi
}

# ----------------------------------------------------------- what is needed

check_tools() {
  if ! command -v docker >/dev/null 2>&1; then
    stop "Docker is not installed. On Ubuntu 26.04: sudo apt install docker.io docker-compose-v2 docker-buildx git. For other systems, selfhost/README.md, Before you install."
  fi
  if ! compose=$(docker compose version --short 2>/dev/null </dev/null); then
    stop "Docker's Compose plugin is not installed: docker compose version does not answer. selfhost/README.md, Before you install, names its package."
  fi
  # Docker answered when it names its version. Its exit code alone does not
  # say so: Debian 13's docker 26.1.5 refuses a user without access with an
  # empty line, the refusal, and exit 0 (measured 2026-10-16).
  server=$(docker info --format '{{.ServerVersion}}' 2>/dev/null </dev/null) || server=
  case $server in
    [0-9]*) ;;
    *)
      say "Docker did not answer:" >&2
      docker info --format '{{.ServerVersion}}' 2>&1 >/dev/null </dev/null | sed -n '1,3s/^/  /p' >&2
      stop "Check that Docker runs: systemctl status docker"
      ;;
  esac
  if ! command -v git >/dev/null 2>&1; then
    stop "git is not installed. It clones the repository and names the commit you built."
  fi
  if ! command -v curl >/dev/null 2>&1; then
    stop "curl is not installed. It asks our probers for this server."
  fi
}

# is_checkout answers whether a folder is a whichports checkout: the two
# files of selfhost/ this installer reads, and git's own folder or file.
is_checkout() {
  [ -f "$1/selfhost/compose.yaml" ] && [ -f "$1/selfhost/env.example" ] && [ -e "$1/.git" ]
}

# find_install sets clone to yes when the folder is not there yet. When it
# is, it is used only as a folder this script made: see check_tree.
find_install() {
  clone=no
  if [ -L "$INSTALL_DIR" ]; then
    stop "$INSTALL_DIR is a link. This installer uses the folder it made there and nothing else. Move the link away, and run the line again."
  elif [ -e "$INSTALL_DIR" ]; then
    check_tree
  else
    clone=yes
  fi
}

# check_tree refuses a folder whose files root would build and run but that
# somebody else could have put there or changed: one where any file, or the
# folder it is in, is not root's or may be written by a group or by anybody,
# and one in which git sees a change or a file it does not know. A link's
# own permission bits mean nothing, so a link is judged by its owner alone.
check_tree() {
  if ! is_checkout "$INSTALL_DIR"; then
    stop "$INSTALL_DIR is there and is not a whichports checkout. Move it away, and run the line again."
  fi
  head=$(git -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null </dev/null) || head=
  if [ "$head" != "$RELEASE_COMMIT" ]; then
    stop "$INSTALL_DIR is at commit ${head:-none git can read}, and this installer is for $RELEASE_TAG, commit $RELEASE_COMMIT. To upgrade, selfhost/README.md, Upgrade. To start again, move it away and run the line again."
  fi
  if ! check_example "$INSTALL_DIR"; then
    stop "$INSTALL_DIR/selfhost/env.example has no single WHICHPORTS_DOMAIN and WHICHPORTS_PROBER_INVITE line, or no WHICHPORTS_HTTPS_PORT=443, so this installer cannot fill it in. Move it away, and run the line again."
  fi
  parent=$(dirname "$INSTALL_DIR")
  others=$(find "$parent" -maxdepth 0 \( ! -user "$ROOT_UID" -o -perm -0020 -o -perm -0002 \) -print)
  others=$others$(find "$INSTALL_DIR" \( ! -user "$ROOT_UID" -o \( ! -type l \( -perm -0020 -o -perm -0002 \) \) \) -print)
  if [ -n "$others" ]; then
    say "Not root's, or writable by others:" >&2
    say "$others" | sed -n '1,5s/^/  /p' >&2
    stop "So somebody other than root could have put there what this installer would build and run as root. Move $INSTALL_DIR away, and run the line again."
  fi
  if ! changes=$(git -C "$INSTALL_DIR" status --porcelain 2>&1 </dev/null); then
    say "$changes" | sed -n '1,3s/^/  /p' >&2
    stop "git could not read $INSTALL_DIR. Move it away, and run the line again."
  fi
  if [ -n "$changes" ]; then
    say "git sees these in $INSTALL_DIR:" >&2
    say "$changes" | sed -n '1,5s/^/  /p' >&2
    stop "So it is not the release as it was cloned, and this installer does not build it. Move it away, and run the line again."
  fi
}

# clone_it clones into a folder of its own beside the install folder, and
# moves the clone into place only once git has finished, so a clone that
# fails leaves nothing behind.
clone_it() {
  say "* cloning $repository at $RELEASE_TAG into $INSTALL_DIR"
  work=$(mktemp -d "$(dirname "$INSTALL_DIR")/.whichports-clone.XXXXXX")
  # A repository that wants a login fails here, with git's own words,
  # rather than asking for one at this terminal.
  if ! GIT_TERMINAL_PROMPT=0 git clone --quiet --no-checkout "$repository" "$work/whichports" </dev/null; then
    rm -rf "$work"
    stop "The clone failed, and git's own words are above."
  fi
  # The tag's commit, as the clone has it, then that commit checked out.
  # Checked out by its hash, and not cloned with --branch, because git
  # warns of an annotated tag that it is not a commit, and then explains a
  # detached HEAD at length, --quiet or not.
  if ! head=$(git -C "$work/whichports" rev-parse --verify --quiet "refs/tags/$RELEASE_TAG^{commit}" </dev/null); then
    rm -rf "$work"
    stop "The tag $RELEASE_TAG is not in $repository. Nothing was built from it."
  fi
  if [ "$head" != "$RELEASE_COMMIT" ]; then
    rm -rf "$work"
    stop "The tag $RELEASE_TAG in $repository names commit $head, and this installer is for commit $RELEASE_COMMIT. Nothing was built from it."
  fi
  git -C "$work/whichports" -c advice.detachedHead=false checkout --quiet "$RELEASE_COMMIT" </dev/null
  if ! check_example "$work/whichports"; then
    rm -rf "$work"
    stop "The release's selfhost/env.example has no single WHICHPORTS_DOMAIN and WHICHPORTS_PROBER_INVITE line, or no WHICHPORTS_HTTPS_PORT=443, so this installer cannot fill it in."
  fi
  changed=yes
  mv "$work/whichports" "$INSTALL_DIR"
  rmdir "$work"
}

# port_is_held answers whether a program on this server listens on a TCP
# port, from the kernel's own tables: a line whose state is 0A, LISTEN, and
# whose local address ends in the port, in hex.
port_is_held() {
  hex=$(printf '%04X' "$1")
  for table in "$PROC_NET/tcp" "$PROC_NET/tcp6"; do
    [ -r "$table" ] || continue
    while read -r _number local _remote state _rest; do
      if [ "$state" = 0A ] && [ "${local##*:}" = "$hex" ]; then
        return 0
      fi
    done <"$table"
  done
  return 1
}

# check_ports stops before anything is asked when a port the stack needs is
# held by another program, or when a stack named whichports runs from another
# folder: Compose gives the project that name wherever it was started, so this
# one would take that stack over, volumes and all. This folder's own stack, on
# a second run, holds its own ports.
check_ports() {
  others=$(docker ps -a -q --filter label=com.docker.compose.project=whichports </dev/null) || others=
  if [ -n "$others" ]; then
    for id in $others; do
      from=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$id" </dev/null) || from=
      if [ "$from" != "$INSTALL_DIR/selfhost" ]; then
        stop "A stack named whichports is on this server already, from ${from:-a folder Docker does not name}. This installer would take it over, so it does not. Take that stack down first, or go on with it by hand."
      fi
    done
    return 0
  fi
  for port in $PORTS; do
    if port_is_held "$port"; then
      stop "Port $port is held by another program on this server, and the stack needs it. Free it first. Behind a proxy of your own, install by hand: selfhost/README.md, Your own proxy."
    fi
  done
}

say_what_it_asks() {
  say "whichports, the self-hosted install"
  say ""
  say "It asks three things: your domain, an email address and a password. Then it says what it will do with them, and changes nothing and sends nothing until you type yes."
  say "Docker $server, Compose $compose."
  say ""
}

# say_the_plan_and_ask_to_go_on shows what will be done with the answers,
# what goes to our probers among them, and goes on only when the person
# types yes.
say_the_plan_and_ask_to_go_on() {
  say ""
  say "It will:"
  if [ "$clone" = yes ]; then
    say "  1. clone $repository at $RELEASE_TAG, commit $RELEASE_COMMIT, into $INSTALL_DIR"
  else
    say "  1. use $INSTALL_DIR, which an earlier run made, as it is"
  fi
  say "  2. write $INSTALL_DIR/selfhost/.env, readable by root only, for $domain"
  say "  3. build the images, start the stack on port 443, and wait until it reads healthy"
  say "  4. make the account $email"
  case $probers_step in
    check) say "  5. ask our probers at $PROBERS whether they still know the line in .env, and if not, ask them for this server: a code goes by mail to $email" ;;
    code) say "  5. ask our probers at $PROBERS for this server with the code they mailed earlier, and mail nothing new" ;;
    *) say "  5. ask our probers at $PROBERS for this server: a code goes by mail to $email" ;;
  esac
  say ""
  ask "Go on? Type yes to go on, anything else stops here:"
  case $answer in
    [Yy][Ee][Ss]) ;;
    *) stop "You did not type yes." ;;
  esac
}

# ---------------------------------------------------------------- the rules
#
# Each rule is the control plane's own, repeated here so that a value of the
# wrong shape stops this script before it changes anything.
# selfhost/test_install.py holds each to the same answers as the code it
# repeats. Each runs in a subshell, so the C locale it sets, where a range
# like a-z is the ASCII letters and nothing else, ends with it.

# name_ok: a plain host name, as the domain and the invite's host both are
# (app/invite.py, host_ok). Lowercase letters, digits and hyphens in labels of
# 1 to 63, no label starting or ending with a hyphen, at least two labels, at
# most 253 characters, and a letter in the last label so that an address is
# never taken for a name.
name_ok() {
  (
    LC_ALL=C
    name=$1
    [ -n "$name" ] && [ "${#name}" -le 253 ] || exit 1
    case $name in *[!a-z0-9.-]*|.*|*.|*..*) exit 1 ;; esac
    case $name in *.*) ;; *) exit 1 ;; esac
    set -f
    IFS=.
    last=
    for label in $name; do
      [ "${#label}" -le 63 ] || exit 1
      case $label in -*|*-) exit 1 ;; esac
      last=$label
    done
    case $last in *[a-z]*) ;; *) exit 1 ;; esac
  )
}

# hex64_ok: exactly 64 lowercase hex characters, the body of a key.
hex64_ok() {
  (
    LC_ALL=C
    case $1 in ''|*[!0-9a-f]*) exit 1 ;; esac
    [ "${#1}" -eq 64 ]
  )
}

# invite_ok: the invite line, whpinvite1_<host>_<API key>_<proof key>
# (app/invite.py). Taken apart and put together again, so a line with
# anything more or less in it is refused.
invite_ok() {
  (
    LC_ALL=C
    line=$1
    case $line in whpinvite1_*) ;; *) exit 1 ;; esac
    rest=${line#whpinvite1_}
    host=${rest%%_*}
    keys=${rest#"$host"_}
    case $keys in whpi_*_whpp_*) ;; *) exit 1 ;; esac
    api=${keys#whpi_}
    api=${api%%_*}
    proof=${keys#whpi_"$api"_whpp_}
    name_ok "$host" && hex64_ok "$api" && hex64_ok "$proof" || exit 1
    [ "$line" = "whpinvite1_${host}_whpi_${api}_whpp_${proof}" ]
  )
}

# email_ok: something, an @, and a name with a dot in it, with no space and
# no second @, at most 255 characters (app/accounts.py, valid_email). A
# control character is refused too, which the control plane would take.
email_ok() {
  (
    LC_ALL=C
    email=$1
    [ "${#email}" -le 255 ] || exit 1
    case $email in *[[:space:]]*|*[[:cntrl:]]*|*@*@*) exit 1 ;; esac
    case $email in ?*@?*) ;; *) exit 1 ;; esac
    case ${email#*@} in ?*.?*) ;; *) exit 1 ;; esac
  )
}

# signup_email_ok: the address our probers' API takes, in its own rule
# (app/betasignup.py, normalise_email), applied to the address in
# lowercase, as the API lowercases it. At most 254 characters. Before the
# one @, at most 64 of the letters, digits and the marks
# ! # $ % & ' * + / = ? ^ _ ` { | } ~ -, in parts joined by single dots.
# After it, two labels or more of letters, digits and inner hyphens, each of
# 1 to 63, and a last one that is not all digits. tr only deletes the
# characters it is given: the address is no secret, and it is never run.
signup_email_ok() {
  (
    LC_ALL=C
    email=$1
    [ -n "$email" ] && [ "${#email}" -le 254 ] || exit 1
    case $email in *@*@*) exit 1 ;; *?@?*) ;; *) exit 1 ;; esac
    local_part=${email%@*}
    domain=${email#*@}
    [ "${#local_part}" -le 64 ] || exit 1
    case $local_part in .*|*.|*..*) exit 1 ;; esac
    others=$(printf '%s' "$local_part" | LC_ALL=C tr -d "a-z0-9.!#\$%&'*+/=?^_\`{|}~-")
    [ -z "$others" ] || exit 1
    case $domain in .*|*.|*..*|*[!a-z0-9.-]*) exit 1 ;; esac
    case $domain in *.*) ;; *) exit 1 ;; esac
    set -f
    IFS=.
    last=
    for label in $domain; do
      [ "${#label}" -le 63 ] || exit 1
      case $label in -*|*-) exit 1 ;; esac
      last=$label
    done
    case $last in *[!0-9]*) ;; *) exit 1 ;; esac
  )
}

# code_ok: the code our probers mail, eight digits.
code_ok() {
  (
    LC_ALL=C
    case $1 in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) exit 1 ;; esac
  )
}

# line_is_ours: an invite line whose host is the one this script calls. A
# line that names another host would send the instance's batches and its
# keys there, so it is never written.
line_is_ours() {
  invite_ok "$1" || return 1
  rest=${1#whpinvite1_}
  [ "${rest%%_*}" = "$PROBERS" ]
}

# password_needs prints what a password lacks, in the control plane's own
# words (app/accounts.py, check_password_shape), or nothing when it has it
# all: at most 128 characters, and at least 12 with a number and a character
# that is not a letter or a digit. The test is exact for the characters on a
# keyboard. A letter or a digit from outside them is counted here by its
# bytes, so for such a password the control plane's own check, when the
# account is made, is the one that decides. Builtins only: no program is
# started with the password.
password_needs() {
  (
    LC_ALL=C
    password=$1
    if [ "${#password}" -gt 128 ]; then
      say "Use at most 128 characters."
      exit 0
    fi
    missing=
    [ "${#password}" -ge 12 ] || missing="at least 12 characters"
    case $password in *[0-9]*) ;; *) missing="${missing:+$missing, }a number" ;; esac
    case $password in *[!A-Za-z0-9]*) ;; *) missing="${missing:+$missing, }a special character" ;; esac
    if [ -n "$missing" ]; then
      say "Needs $missing."
    fi
  )
}

# ------------------------------------------------------------ the questions

# ask puts one answer from the terminal in $answer, without the spaces
# around it or the carriage return a paste from another system can carry.
ask() {
  printf '%s ' "$1" >/dev/tty
  answer=
  read -r answer </dev/tty || answer=
  answer=${answer%"$(printf '\r')"}
}

# ask_secret puts one answer in $secret, exactly as typed, read with the
# terminal's echo off so it is never shown. The echo goes off before the
# question is shown, so nothing typed after it can be shown either.
ask_secret() {
  if ! stty -echo </dev/tty; then
    stop "The terminal's echo could not be turned off, so no password is asked for here."
  fi
  printf '%s ' "$1" >/dev/tty
  secret=
  IFS= read -r secret </dev/tty || secret=
  stty echo </dev/tty
  printf '\n' >/dev/tty
}

lowercase() {
  printf '%s' "$1" | LC_ALL=C tr 'A-Z' 'a-z'
}

# again counts one wrong answer, and stops at the third.
again() {
  tries=$((tries + 1))
  if [ "$tries" -ge "$TRIES" ]; then
    stop "Three answers that could not be used. Run the line again."
  fi
}

ask_domain() {
  tries=0
  while :; do
    ask "Your domain, whose A record points at this server:"
    domain=$(lowercase "$answer")
    if name_ok "$domain"; then
      return 0
    fi
    case $answer in
      '') refuse "The domain is needed: the name your dashboard will answer on." ;;
      *://*|*/*) refuse "Type the name alone, without https:// and without a slash." ;;
      *) refuse "That is not a domain name, such as whichports.example.com." ;;
    esac
    again
  done
}

# ask_email takes an address the account and our probers' API both take,
# since the code for our probers is mailed to it.
ask_email() {
  tries=0
  while :; do
    ask "An email address for your account:"
    email=$answer
    signup_email=$(lowercase "$email")
    if email_ok "$email" && signup_email_ok "$signup_email"; then
      return 0
    fi
    refuse "That is not an email address."
    again
  done
}

ask_password() {
  tries=0
  while :; do
    ask_secret "A password for it, at least 12 characters, with a number and a special character:"
    password=$secret
    needs=$(password_needs "$password")
    if [ -n "$needs" ]; then
      refuse "$needs"
    else
      ask_secret "The same password again:"
      if [ "$secret" = "$password" ]; then
        secret=
        return 0
      fi
      refuse "The two passwords differ."
    fi
    secret=
    password=
    again
  done
}

# ------------------------------------------------------------- the settings

# check_example answers whether a checkout's env.example has the two lines
# this installer fills in, once each, and Caddy on 443 and nowhere else. One
# from before the invite line has not, and is refused rather than guessed
# at. 443 because the certificate authority's check of the certificate comes
# to 443 (selfhost/Caddyfile), so the one line never moves Caddy.
check_example() {
  example=$1/selfhost/env.example
  domains=0
  invites=0
  ports=0
  while IFS= read -r line || [ -n "$line" ]; do
    case $line in
      WHICHPORTS_DOMAIN=*) domains=$((domains + 1)) ;;
      WHICHPORTS_PROBER_INVITE=*) invites=$((invites + 1)) ;;
      WHICHPORTS_HTTPS_PORT=443) ports=$((ports + 1)) ;;
      WHICHPORTS_HTTPS_PORT=*) ports=$((ports + 2)) ;;
    esac
  done <"$example"
  [ "$domains" -eq 1 ] && [ "$invites" -eq 1 ] && [ "$ports" -eq 1 ]
}

# render_env writes the .env these answers make: env.example as it is, with
# the domain and the invite on their own lines. The three prober lines stay
# empty, because the control plane refuses them beside the invite.
render_env() {
  while IFS= read -r line || [ -n "$line" ]; do
    case $line in
      WHICHPORTS_DOMAIN=*) printf 'WHICHPORTS_DOMAIN=%s\n' "$domain" ;;
      WHICHPORTS_PROBER_INVITE=*) printf 'WHICHPORTS_PROBER_INVITE=%s\n' "$invite" ;;
      *) printf '%s\n' "$line" ;;
    esac
  done <"$INSTALL_DIR/selfhost/env.example"
}

# env_invite prints the invite line an .env holds, or nothing.
env_invite() {
  while IFS= read -r line || [ -n "$line" ]; do
    case $line in
      WHICHPORTS_PROBER_INVITE=*)
        printf '%s' "${line#WHICHPORTS_PROBER_INVITE=}"
        return 0
        ;;
    esac
  done <"$1"
}

# write_env writes .env when there is none, leaves it when it holds exactly
# what these answers make, and otherwise stops before changing anything:
# somebody edited it, or it was written with other answers, and either way
# it is theirs. The one line an earlier run may have filled in is our
# probers' invite line, so an .env whose line is empty or one for our
# probers' host counts as these answers. Any other line there was put in by
# hand.
write_env() {
  if [ -e "$env_file" ]; then
    if { [ -z "$invite" ] || line_is_ours "$invite"; } \
        && [ "$(cat "$env_file")" = "$(render_env)" ]; then
      say "* $env_file is there with these answers, left as it is"
      chmod 600 "$env_file"
      return 0
    fi
    stop "$env_file is there and holds something other than these answers: it was edited, or written with other ones. It was left as it is. To keep it, go on by hand: selfhost/README.md, By hand. To start again with these answers, move it away first: mv $(quoted "$env_file") $(quoted "$env_file.before")"
  fi
  say "* writing $env_file, readable by root only"
  changed=yes
  put_env
}

# put_env writes .env as render_env makes it. It is written beside itself
# and moved into place, so it is never there half written, and it is
# readable by its owner alone from the moment it exists, because it holds
# both prober keys once our probers' line is in it.
put_env() {
  tmp=$(mktemp "$INSTALL_DIR/selfhost/.env.XXXXXX")
  render_env >"$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$env_file"
}

# ------------------------------------------------------------- the stack

# compose runs Docker Compose on the release's own compose file and on it
# alone. Without -f, Compose also reads a compose.override.yaml it finds
# beside compose.yaml, and only the release's own file decides what runs.
compose() {
  docker compose -f "$INSTALL_DIR/selfhost/compose.yaml" "$@"
}

build_and_start() {
  # The commit the dashboard's footer names.
  commit=$(git -C "$INSTALL_DIR" rev-parse --short=12 HEAD 2>/dev/null </dev/null) || commit=
  if [ -z "$commit" ]; then
    say "* git could not read the commit, so the dashboard will name none"
  fi
  # What Docker prints while it builds and starts the stack goes to this
  # file, readable by root alone, so the terminal shows one line a step.
  # It is shown whole only when a step fails. Each run's starts empty.
  log=$INSTALL_DIR/selfhost/install.log
  (umask 077 && : >"$log")
  chmod 600 "$log"
  say "* building the images, a minute or two the first time"
  changed=yes
  if ! WHICHPORTS_COMMIT=$commit compose build >>"$log" 2>&1 </dev/null; then
    show_log
    stop "The build failed, and Docker's own words are above, kept in $log. The settings are written. When it is fixed, run the line again."
  fi
  say "* starting the stack, and waiting at most $WAIT_SECONDS seconds until it reads healthy"
  start_stack "No account was made."
  say "* healthy, and it stayed up"
}

# start_stack starts the stack, or starts it again with what .env now says,
# and waits until it reads healthy and stays up. When it does not, it stops
# the installer, with its one argument as the last thing said: what was not
# done, or what was.
start_stack() {
  if ! WHICHPORTS_COMMIT=$commit compose up -d --wait --wait-timeout "$WAIT_SECONDS" >>"$log" 2>&1 </dev/null; then
    show_log
    say "The stack did not come up healthy. Compose waits at most $WAIT_SECONDS seconds, and its own words are above, kept in $log. What it says now:" >&2
    say "  cd $(quoted "$INSTALL_DIR/selfhost")" >&2
    say "  docker compose ps" >&2
    say "  docker compose logs controlplane caddy" >&2
    stop "$1 When it is fixed, run the line again."
  fi
  if ! stays_up; then
    say "The stack did not stay up. Each container, its state, its health and how often it restarted, read $STEADY_SECONDS seconds apart:" >&2
    say "$first" | sed 's/^/  /' >&2
    say "$second" | sed 's/^/  /' >&2
    say "What it says:" >&2
    say "  cd $(quoted "$INSTALL_DIR/selfhost")" >&2
    say "  docker compose ps" >&2
    say "  docker compose logs controlplane caddy" >&2
    stop "$1 When it is fixed, run the line again."
  fi
}

# show_log prints what Docker said, all of it, for a step that failed.
show_log() {
  sed 's/^/  /' "$log" >&2
}

# container_states prints one line for each container of the stack: its
# name, its state, its health or none, and how often Docker restarted it.
container_states() {
  ids=$(compose ps -a -q </dev/null) || return 1
  [ -n "$ids" ] || return 1
  for id in $ids; do
    docker inspect --format '{{.Name}} {{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} {{.RestartCount}}' "$id" </dev/null || return 1
  done
}

# stays_up answers whether, read twice STEADY_SECONDS apart, every container
# runs, every one with a health check reads healthy, and none restarted in
# between. It reads the containers themselves, not what Compose said.
stays_up() {
  first=$(container_states) || return 1
  sleep "$STEADY_SECONDS"
  second=$(container_states) || return 1
  [ "$first" = "$second" ] || return 1
  while read -r _name status health _restarts; do
    [ "$status" = running ] || return 1
    case $health in healthy|none) ;; *) return 1 ;; esac
  done <<STATES
$second
STATES
}

# make_account makes the first account, at this terminal. When the instance
# has an account already, it makes none: the person who installed it signs
# in with theirs, and users_cli adds more.
make_account() {
  say "* making your account"
  # list refuses when there is no database yet, which is the first run.
  if listed=$(compose exec -T controlplane python -m app.users_cli list 2>/dev/null </dev/null); then
    has_database=yes
  else
    has_database=no
    listed=
  fi
  if [ -n "$listed" ]; then
    wanted=$(lowercase "$email")
    found=no
    while read -r first rest; do
      if [ "$first" = "$wanted" ]; then
        found=yes
      fi
    done <<LISTED
$listed
LISTED
    if [ "$found" = yes ]; then
      say "* the account $email is there already, left as it is"
    else
      say "* this instance has an account already, so none was made for $email."
      say "  To add it: docker compose exec controlplane python -m app.users_cli add $(quoted "$email")"
    fi
    password=
    return 0
  fi
  # The password goes in on standard input, one line, which is how the
  # control plane takes it from a pipe (app/users_cli.py). printf is a
  # builtin, so no program is started with it on its command line.
  if [ "$has_database" = yes ]; then
    if ! printf '%s\n' "$password" | compose exec -T controlplane python -m app.users_cli add -- "$email"; then
      password=
      stop "The account was not made, for the reason above. The stack runs. Run the line again, or make it by hand: docker compose exec controlplane python -m app.users_cli add $(quoted "$email")"
    fi
  else
    if ! printf '%s\n' "$password" | compose exec -T controlplane python -m app.users_cli --create-database add -- "$email"; then
      password=
      stop "The account was not made, for the reason above. The stack runs. Run the line again, or make it by hand: docker compose exec controlplane python -m app.users_cli add $(quoted "$email")"
    fi
  fi
  password=
}

# ------------------------------------------------------------- our probers

# find_probers reads, before the plan and without sending anything, what this
# run has to do with our probers: ask whether they still know the line an
# earlier run wrote, ask for the code of a claim our API took less than a
# day ago, or sign up.
find_probers() {
  env_file=$INSTALL_DIR/selfhost/.env
  claim_file=$INSTALL_DIR/selfhost/.prober-claim
  invite=
  if [ -f "$env_file" ]; then
    invite=$(env_invite "$env_file")
  fi
  if [ -n "$invite" ]; then
    probers_step=check
  elif claim_is_fresh; then
    probers_step=code
  else
    probers_step=signup
  fi
}

# claim_is_fresh answers whether a claim an earlier run kept is there, is
# one, is less than a day old and was made for the address given this time,
# and puts it in $claim. A claim made for another address, a mistyped one
# say, is left: this run signs up with the address it was given.
claim_is_fresh() {
  [ -f "$claim_file" ] || return 1
  [ -n "$(find "$claim_file" -mmin "-$CLAIM_MINUTES" -print 2>/dev/null </dev/null)" ] || return 1
  claim=
  claimed_for=
  { read -r claim && read -r claimed_for; } <"$claim_file" || :
  hex64_ok "$claim" && [ "$claimed_for" = "$signup_email" ]
}

# use_our_probers does the plan's last step. It keeps a line our probers
# still know, or gets one with the code from the mailbox, writes it into
# .env and starts the stack again with it. Every way it gets none is one
# line, and the install goes on without our probers.
use_our_probers() {
  emptied=no
  if [ "$probers_step" = check ]; then
    case $(line_known) in
      yes)
        say "* our probers know the line in $env_file, left as it is"
        rm -f "$claim_file"
        return 0
        ;;
      no)
        say "* our probers no longer know the line in $env_file, so it is emptied"
        invite=
        put_env
        emptied=yes
        probers_step=signup
        if claim_is_fresh; then
          probers_step=code
        fi
        ;;
      *)
        say "* our probers could not be asked about the line in $env_file, left as it is"
        return 0
        ;;
    esac
  fi
  if ! get_a_line; then
    if [ "$emptied" = yes ]; then
      say "* starting the stack again without it"
      start_stack "The line in $env_file is emptied."
    fi
    return 0
  fi
  say "* writing our probers' line into $env_file"
  put_env
  # The line is kept, so the claim's work is done. A run after this one
  # asks our probers about the line, never with the claim.
  rm -f "$claim_file"
  say "* starting the stack again with it"
  start_stack "Our probers' line is in $env_file."
  say "* healthy, and it stayed up, with our probers"
  # The claim's hour of fresh keys ends here. Its answer changes nothing.
  printf '{"claim":"%s"}' "$claim" | ask_probers "$DONE_PATH" >/dev/null || :
  claim=
}

# get_a_line signs up when this run has no claim yet, then asks for the
# code. It puts the line in $invite, or says why there is none.
get_a_line() {
  if [ "$probers_step" = signup ]; then
    sign_up || return 1
  fi
  collect_with_a_code
}

# sign_up sends our API the address and a new claim, and keeps the claim
# when our API took it. No other answer leaves a claim behind.
sign_up() {
  say "* signing up for our probers with $email"
  claim=$(new_claim) || claim=
  if ! hex64_ok "$claim"; then
    say "No random claim could be made on this server. The install goes on without our probers."
    return 1
  fi
  reply=$(printf '{"email":"%s","claim":"%s"}' "$signup_email" "$claim" | ask_probers "$SIGNUP_PATH") || reply=
  if [ "$reply" != sent ]; then
    say_why_not "$reply"
    return 1
  fi
  # A function called from an if runs without set -e, so a claim that could
  # not be written, on a full disk say, is said here.
  if ! keep_claim; then
    say "The claim could not be kept on this server. The install goes on without our probers."
    return 1
  fi
}

# collect_with_a_code asks for the code, at most CODE_TRIES times, and sends
# it with the claim. A code that is not eight digits, spaces and dashes
# aside, is not sent, and counts as one that did not work.
collect_with_a_code() {
  tries=0
  while :; do
    ask "Type the 8-digit code from your mail, or press Enter to skip:"
    if [ -z "$answer" ]; then
      say "The install goes on without our probers. Run the same line again to type the code."
      return 1
    fi
    code=$(printf '%s' "$answer" | LC_ALL=C tr -d ' -')
    reply=wrong
    if code_ok "$code"; then
      reply=$(printf '{"claim":"%s","code":"%s"}' "$claim" "$code" | ask_probers "$COLLECT_PATH") || reply=
      # No answer may still have made the instance: asked once more with
      # the same claim, our API gives fresh keys for it.
      if [ -z "$reply" ]; then
        reply=$(printf '{"claim":"%s","code":"%s"}' "$claim" "$code" | ask_probers "$COLLECT_PATH") || reply=
      fi
    fi
    code=
    case $reply in
      wrong)
        tries=$((tries + 1))
        if [ "$tries" -ge "$CODE_TRIES" ]; then
          say "Five codes did not work. The install goes on without our probers. Run the same line again tomorrow."
          return 1
        fi
        refuse "That code did not work."
        ;;
      whpinvite1_*)
        if line_is_ours "$reply"; then
          invite=$reply
          reply=
          return 0
        fi
        say_why_not unreachable
        return 1
        ;;
      *)
        say_why_not "$reply"
        return 1
        ;;
    esac
  done
}

# say_why_not says, in one line, what one answer of our API means for the
# install. Anything that is not one of its words, no answer among them,
# reads as our probers not being reached.
say_why_not() {
  case $1 in
    full_today) say "Our probers are full for today. The install goes on without them. Run the same line again tomorrow." ;;
    full) say "Our probers have no room. The install goes on without them." ;;
    closed) say "Signing up for our probers is closed. The install goes on without them." ;;
    invalid_email) say "Our probers cannot mail that address. The install goes on without them." ;;
    *) say "Our probers could not be reached. The install goes on without them. Run the same line again later." ;;
  esac
}

# new_claim prints 32 random bytes from the kernel as 64 hex characters.
new_claim() {
  od -An -N32 -tx1 /dev/urandom </dev/null | LC_ALL=C tr -d ' \n'
}

# keep_claim writes the claim beside .env, with the address it was made
# for, readable by root alone from the moment it exists, so a run inside its
# day with that address asks for the code again.
keep_claim() {
  tmp=$(mktemp "$INSTALL_DIR/selfhost/.prober-claim.XXXXXX") || return 1
  printf '%s\n%s\n' "$claim" "$signup_email" >"$tmp" || return 1
  chmod 600 "$tmp" || return 1
  mv -f "$tmp" "$claim_file"
}

# ask_probers posts what comes on its standard input to one route of our
# probers' API and prints the answer. curl's own words go nowhere: every
# way a call fails is one line, which the caller says. -q, first, keeps
# root's own .curlrc out of the call, so no setting of it changes the TLS
# the claim and the code travel under or writes them to a file.
ask_probers() {
  curl -q --proto '=https' --tlsv1.2 -fsS --connect-timeout "$CONNECT_SECONDS" --max-time "$CALL_SECONDS" \
    -H 'Content-Type: application/json' --data-binary @- "https://$PROBERS$1" 2>/dev/null
}

# line_known prints yes when our probers take the API key of the line in
# .env, no when they refuse it as unknown, which a revoked key reads as too,
# and nothing when they could not be asked. The key reaches curl on its
# standard input, as a header.
line_known() {
  rest=${invite#whpinvite1_}
  keys=${rest#*_}
  key=${keys%%_whpp_*}
  status=$(printf 'Authorization: Bearer %s\n' "$key" | curl -q --proto '=https' --tlsv1.2 -fsS \
    --connect-timeout "$CONNECT_SECONDS" --max-time "$CALL_SECONDS" -o /dev/null \
    -w '%{http_code}' -H @- "https://$PROBERS$VANTAGES_PATH" 2>/dev/null) || :
  key=
  case $status in
    200) say yes ;;
    401) say no ;;
  esac
}

say_done() {
  say ""
  say "whichports is running."
  say "  open      https://$domain/"
  say "  sign in   $email"
  say "  settings  $INSTALL_DIR/selfhost/.env"
  say "  folder    $INSTALL_DIR/selfhost, where the README's docker compose commands run"
  say ""
  say "The first load can take a moment, because Caddy has to get its certificate first, and docker compose logs caddy says where it is. Then Add server, and run the line it gives you on that server."
}

# The call, inside braces for the reason given above main: cut this line
# short anywhere and the shell has an unfinished group and runs nothing.
{ main "$@"; }
