# agent

The whichports host collector. A single static Go binary that reads every
filtering layer on one Linux host and prints one JSON document. It is intended to
become public, so it is kept separable from the rest of the repo from day one.

## What it does, and the line it never crosses

It **reads**. Listening sockets with their owning process and uid, the nftables ruleset,
iptables and ip6tables, ufw and firewalld, Docker and Podman chains, overlay
tables, and which package dpkg's records say owns the program behind each
listening service. Of the sets a ruleset holds it reads one kind: the conntrack states of
an anonymous set a rule looks a state up in, so `ct state { new, untracked }`
reads as written. A set of addresses is never read, and shows as
`[lookup @name]`. It never executes another program, never opens a listening socket, never
writes a rule, and holds none of your credentials. The secrets it can store are
its own whichports credential, which authorises posting this host's report and
nothing else, and on a host whose control plane uses whichports' probers a proof
key, which authorises saying which public addresses the host holds and nothing
else. The full boundary is the eight security invariants, stated in code in
`internal/safety`, and the test suite fails the build if any of it is violated.

When it reports, the channel is one-way by construction: outbound HTTPS POSTs
only, and the agent parses no byte of any response, ever. Even enrollment is offline,
a local file write of a credential the dashboard generated. The code is
`internal/report`.

The read mechanism is direct: netlink, getsockopt, `/proc`, config files. Never a
shell-out to `ss`, `nft` or `ufw`.

## Layout

```
cmd/agent          the binary and its run modes
internal/hostdoc   the host document: the versioned JSON contract
internal/safety    the security boundary, as an in-code manifest the tests enforce
reference/         recon.sh, read-only notes on what to read. NOT a deliverable
SECURITY-REVIEW.md what was checked, what was found, what root it keeps and why
```

`SECURITY-REVIEW.md` is the answer to "what does this run as on my server". It
says which capability each read needs, measured rather than assumed, what the
systemd unit takes away, and where the remaining privilege actually goes. It
also names what was not measured.

## Run modes

```
agent --mode=stdout    read, print the document, send nothing off the
                       machine. The default. It does not read the enrolment
                       file, and the only connections it opens are local:
                       one GET each to the Docker and Podman sockets, where
                       they exist.
agent --mode=oneshot   read once and deliver to the control plane. For cron,
                       Ansible, an RMM. Errors if the host is not enrolled.
agent --mode=timer     the packaged systemd-timer mode: write the document to
                       /var/lib/whichports/host.json atomically, then deliver
                       it only if the host is enrolled. Un-enrolled, nothing
                       leaves the machine.
agent enroll           connect this host: write /etc/whichports/agent.conf
                       from --server and --credential, readable by root and
                       by the packaged unit's own user and nobody else, and
                       add search on /etc/whichports so that user can reach
                       it whatever umask enroll ran under.
                       Offline, a local file write. The credential comes from
                       the dashboard's add-host screen and authorises only
                       posting this host's own report.
agent --version        print one line saying what the binary is: the package
                       version, plus the commit, commit time and clean or
                       modified state the Go toolchain recorded at build time.
                       Anything the build did not record says unknown. Nothing
                       is collected and nothing is sent.
```

`internal/report` is the only place in the agent allowed to speak HTTP to the
network, enforced by `internal/safety`. Each run sends the report, then one
empty presence request over each address family so a dual-stack host proves
both its addresses. On a host whose control plane uses whichports' probers it
first sends one request over each family to the prober API, carrying the
public addresses on the host's interfaces and nothing else, because those are
the addresses the probers are asked to probe. All of it outbound, TLS 1.2
floor, redirects never followed, and no byte of any response is ever parsed.

## Build and test

```
go vet ./... && go test ./...                          # includes the security scan
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/agent   # the static build the page promises
```

In the development tree a commit gate runs the first line for every
commit that holds a file under `agent/`: `go vet`, `go vet` for Linux and
`go test -race`, once as the files are and once more with each build tag it
finds in the tree, of which there is none. It does not run the tests that are built on Linux only, nor
the clean-box harness in `ops/cleanbox`, and it prints that on every run. Run
those two by hand, on Linux, before a change under `agent/` lands, and the
static build with them. The static build and the security tests are hard
gates: a change that fails either does not land.

The package reader, `internal/collect/packages.go`, and the apt lists reader
beside it, `internal/collect/aptlists.go`, are in every build, and a report
carries a `packages` section. A release is built with no build tag, and
`ops/require-reproducible-binary.sh` refuses a release binary built with
one. Some collector tests are built on Linux only, so make the run on Linux
too.

## Packaging

```
make package          # unsigned .deb + .rpm into dist/, for hands-on testing
make package-signed   # release build, key handling in packaging/signing/README.md
```

One spec (`packaging/nfpm.yaml`), no dpkg or rpm toolchains, and no runtime
dependencies because the binary has none. The package ships the binary plus a
systemd service and timer that write the document to
`/var/lib/whichports/host.json` every fifteen minutes, atomically, and the
timer is off until the operator enables it. The install creates a dedicated
system user, `whichports-agent`, and the service runs as that user with
exactly two capabilities, CAP_NET_ADMIN and CAP_NET_RAW. The hosted apt and
dnf repository is an open decision on the board.

## What the non-root agent sees, and the two grants the installer gives it

Measured, not reasoned: on 2026-08-19 the agent ran as an unprivileged user
with those two capabilities on both distro families. Every
listening port, every bind address and every live kernel rule collects. What
does not collect is reported as `permission_denied` in the document, never
guessed. Four things sit behind ordinary file permissions:

- ufw's declared rules: `/etc/ufw/user.rules` and `user6.rules` are 640 root
  root on Ubuntu
- firewalld's configuration: `/etc/firewalld` is 750 root root on AlmaLinux,
  so the admin zones and `firewalld.conf` are unreadable, and so are the rule
  file mtimes on that family
- the container runtimes: the rootful Podman socket is 0660 root root, and
  the Docker socket belongs to the `docker` group
- the kernel's list of its legacy iptables tables: `/proc/net/ip_tables_names`
  and `ip6_tables_names` are 0440 root root, and a file under `/proc` takes no
  grant (`setfacl` answers "Operation not supported"). The agent asks the
  kernel about a legacy table only when that list names it, because asking
  about a missing table makes the kernel create it. Without the list, the
  loaded modules decide: with ip_tables loaded as a module and no `iptable_`
  module beside it, there is no legacy table, and that collects as
  `not_present`. A loaded `iptable_` module, or ip_tables built into the
  kernel, makes that table `permission_denied`

The live rules still arrive over netlink in the two firewall cases, and a
port a container publishes still shows in the socket list, it just loses the
line saying which container published it. What the grants restore is the
declared side, the files an admin wrote and the runtime's own account, so
the control plane can compare what was declared against what the kernel is
doing.

**The two firewall grants are applied by the installer**, since 2026-09-13
(the owner's decision: the firewall's rules are the core of the product).
Each is one read-only ACL entry, applied only where
the target exists, visible with `getfacl` and taken back with `setfacl -x`,
and `whichports-uninstall` takes them all back. Read and never write: `r` on
a file, `rx` on a directory because entering one needs `x`. Re-running the
installer converges, because `setfacl -m` replaces an entry that is already
there. `setfacl` comes from the `acl` package, which the agent package
depends on. Where a target is a symlink, the installer follows it only to a
file in the same directory, which is how Fedora ships `firewalld.conf`, and
puts the grant on that file. Any other symlink stops the installer with
nothing granted on it. This is what the installer runs:

```
setfacl -m u:whichports-agent:r /etc/ufw/user.rules /etc/ufw/user6.rules
setfacl -m u:whichports-agent:rx /etc/firewalld /etc/firewalld/zones
setfacl -m u:whichports-agent:r /etc/firewalld/firewalld.conf /etc/firewalld/zones/*.xml
```

A firewalld zone file added later does not inherit the grant: run the
installer again, or the third line by hand.

**The two runtime grants are yours to give**, because a runtime socket does
not distinguish reading from writing and a grant on it is access to the
runtime. The agent sends one GET and the source shows it, but the grant
itself is the group, not the GET.

**Docker's published ports.** Widens: membership of the `docker` group.

```
usermod -aG docker whichports-agent
```

**Podman's published ports (rootful).** Widens: the same, for the Podman API
socket. The directory line matters as much as the socket line, because
`/run/podman` is 700 root root and a grant on the socket alone changes
nothing (measured 2026-08-19).

```
setfacl -m u:whichports-agent:x /run/podman
setfacl -m u:whichports-agent:rw /run/podman/podman.sock
```

`/run` is a tmpfs, so the two Podman lines do not survive a reboot. The
durable form is a drop-in on Podman's socket unit that applies the grant
whenever the socket is created, and that drop-in is not shipped yet.

With every grant above given, the non-root document was measured equal to
the root document except process names and timestamps (2026-08-19).

### The unit behind a port, at no privilege

The document names the systemd unit that owns each listening socket, and it
costs no capability at all. The kernel puts the cgroup id of every socket
into every sock_diag reply with no capability check, the id resolves to a
directory on the cgroup2 mount, and on a systemd host that directory is the
unit: `caddy.service`, `ssh.socket`, `systemd-resolved.service`
(the fields `cgroup` and `unit` of the document). Measured on 2026-09-12 as the agent's own user with an
empty capability set: every listening socket named on both distro families.

The process name column that needed `CAP_DAC_READ_SEARCH` and
`CAP_SYS_PTRACE` together is not offered any more. Until 0.1.10 an installer
flag, `--full-visibility`, raised the unit to those four capabilities, and
`SECURITY-REVIEW.md` is the account of what a process holding them can do:
read any file and any process's memory on the host. The unit column says
more than the process name did, `ssh.socket` where the pair said `sshd`, and
asks for nothing, so the flag is gone and the installer has no option that
changes what it installs. Run with no arguments it installs and starts
nothing. Run as `install.sh enroll --server=... --credential=...`, which is
the line the dashboard hands out, it installs, runs `whichports-agent enroll`
with those same flags, turns the timer on and collects once. Anything else
on its command line stops it before it fetches anything.

Where the unit column is empty, it is empty and never guessed: a kernel
before 5.8 sends no cgroup id, so RHEL 8 and CentOS 7 name nothing; a cgroup
v1 host has no mount to resolve against; a Docker published port names
`docker.service`, and the container is in the containers section as before.
The sockets section carries a verdict per read, `sock_diag` and `cgroup2`,
so a refused read and a kernel that named nothing read differently.

**If a host was widened before 0.1.10**, the drop-in the old flag wrote is
still there after an upgrade, because a package upgrade leaves an operator's
drop-in alone. Taking it back is these lines, run for the paths the host
has. The package's post-remove and `whichports-uninstall` run the same on a
removal:

```
rm /etc/systemd/system/whichports-agent.service.d/full-visibility.conf
systemctl daemon-reload
```

And the grants above, the installer's two and the runtime ones, are taken
back with these lines, which `whichports-uninstall` runs for you:

```
setfacl -x u:whichports-agent /etc/ufw/user.rules /etc/ufw/user6.rules
setfacl -x u:whichports-agent /etc/firewalld /etc/firewalld/zones \
  /etc/firewalld/firewalld.conf /etc/firewalld/zones/*.xml
setfacl -x u:whichports-agent /run/podman /run/podman/podman.sock
gpasswd -d whichports-agent docker
```

Removing an ACL entry that was never granted is not an error, setfacl
documents this, so the setfacl lines run as written on any host. Removing
the package takes the drop-in and the grants away the same way, and an
upgrade touches neither.

### The package behind a service, from dpkg's own records

For each systemd service that holds a listening socket, the document says
which package dpkg's records name as the owner of the service's unit file and
of the program its ExecStart starts, with the version, source package and
architecture the status file gives them (the section `packages`). It reads
files and never runs dpkg-query: `/var/lib/dpkg/status`, the file lists in
`/var/lib/dpkg/info`, `/var/lib/dpkg/diversions`, the unit files and their
drop-ins, the first four bytes of the program to tell a compiled program from
a script, and `/etc/os-release` for the distribution and its release. Every
one is world readable on Debian and Ubuntu, so this costs the agent's user
nothing.

A service systemd starts on demand counts while its socket unit holds a
listening socket: the kernel reports that socket under the socket unit, and
the socket unit's file names the service. A socket unit that is installed
and holds no socket names nothing, so software that nothing listens for is
not in the section.

What leaves the machine with it, all of it printed by stdout mode so it can be
read on the host before enrolling: package names, versions, source packages
and architectures, the distribution's ID and release, the unit file's path,
and the program path ExecStart names. Never the arguments after that path,
which can hold a password or a token.

It reports and never concludes. Where a step has no answer the entry says
which, from one closed list in `internal/hostdoc/packages.go`: no unit file, a
drop-in that sets ExecStart, more than one command, a special prefix, a path
past its cap, and so on. A program no package installed has no owner, a path
dpkg has diverted says so, a service inside a container or a user's own
service gets no entry, and rpm's records are not read, so a host of the RHEL
family carries the distribution and no entries.

### What the server's own package lists offer, from apt's files

For each package the section above names, a build with the readers also says
which versions the server's own apt lists offer for it (the entry `offers` of
the section `packages`). It reads files and never runs apt: the `Packages`
lists under `/var/lib/apt/lists`, each as a stream and never whole, and each
archive's `InRelease` or `Release` file there. They are world readable on
Debian and Ubuntu.

What leaves the machine with it, all of it printed by stdout mode. For an
archive of the distribution's own: each version it offers, one of three words
for the archive (`debian`, `debian-security`, `ubuntu`), and that archive's
two flags `NotAutomatic` and `ButAutomaticUpgrades`, each a yes or a no. For
all the other archives together two facts a package, each a yes or a no, and
nothing else: whether any of them offers the package at all, and whether any
of them offers the version that is installed. Never an archive's name or
address, a field of its Release file, a list's file name, or a version
another archive offers.

An archive is the distribution's own only when its Release file gives the
distribution's origin and label and the release the server runs, on a server
of that distribution. And a list is that archive's only when the archive's
Release file names it among its files. A list no Release file names counts
as another archive's. Anybody who runs an archive can write those words. So
this follows what the server's own apt was set up with and accepted, and no
more than that. The files are read the way apt 2.6.1 was measured to read
them: a field's name in any case, and a flag as yes for the values apt takes
as yes.

It is all or nothing. The offers are there only when every list in the folder
was read whole. One list kept compressed, one that is not a plain file, one
that is not a list, one past its cap, or one apt replaced during the read,
and there are no offers at all, and the source `apt_lists` says which way the
read went. A version standing in the one list that was not read would
otherwise be reported as not offered.

One such case comes from apt itself. For an archive set up with a `file:`
address apt keeps each list as a link out of the folder, measured with apt
2.6.1. The reader follows no link. So a server with such an archive has no
offers, and `apt_lists` says `read_error`.

The lists are large, about a hundred megabytes on one server read, and the
agent's process ends after each report. So timer mode keeps what it read in
one file of its own beside the document, `/var/lib/whichports/apt-lists.json`:
each list's name, size and time, and the versions found in it for the
packages asked for. A list is opened again only when its size or its time
changed, or when a package is asked for that was not asked for before. The
file is believed only where it is exactly what the reader writes, and it
never leaves the machine. The other two modes keep nothing and write nothing.

## License

Apache-2.0 (`LICENSE`). Decided 2026-08-13, RECORD.md 4.29: the page promises
readable source, and a patent grant is the version of that promise a cautious
buyer's lawyer reads.
