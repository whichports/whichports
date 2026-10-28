# Agent security review, 2026-08-15

The agent runs as root, on a timer, on servers that are not ours. Two questions
follow from that and this document answers both:

1. Are the things it is built from current, and does anything in them have a
   known hole that this code can actually reach?
2. Does it need to be root, and if it does, how much of root does it keep?

Everything below is either read from a primary source that is named, or
measured on a running Linux host and the command is written down so anyone can
run it again. Where a thing was not measured, it says so instead of sounding
confident.

The review was asked for because a sceptical reader raised it, in these terms:
the agent has high privileges even with no inbound connection, and it depends
on other people's code that has to stay current. Both halves are fair, and the
answer to the second one is more interesting than the answer to the first.

## How to check any of this yourself

```sh
cd agent
go run golang.org/x/vuln/cmd/govulncheck@latest ./...   # known holes, reachable ones only
go test ./...                                           # includes the boundary scan
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/agent
systemd-analyze security whichports-agent.service       # on a host with the unit installed
systemd-analyze verify whichports-agent.service         # every line that host's systemd does not know
```

The first and second now run in CI on every change, so neither depends on
anyone remembering.

## 1. What it is built from

The agent has **one direct dependency**, `github.com/google/nftables`. Six
third party modules end up in the binary, because that one brings five with
it. The full list, checked with
`CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go list -deps ./cmd/agent`:

| Module | Was | Dated | Now | Dated | Why it is there |
|---|---|---|---|---|---|
| github.com/google/nftables | v0.3.0 | 2025-02-03 | v0.3.0 | 2025-02-03 | the nf_tables netlink dump. Already the newest release |
| github.com/mdlayher/netlink | v1.7.3-0.20250113171957-fbb4dce95f42 | 2025-01-13 | v1.11.2 | 2026-05-16 | netlink transport, pulled in by nftables |
| github.com/mdlayher/socket | v0.5.0 | 2023-08-31 | v0.6.1 | 2026-05-26 | socket handling, pulled in by netlink |
| golang.org/x/net | v0.33.0 | 2024-12-18 | v0.58.0 | 2026-08-12 | only `x/net/bpf`, pulled in by netlink |
| golang.org/x/sync | v0.6.0 | 2023-12-07 | v0.22.0 | 2026-07-01 | only `x/sync/errgroup` |
| golang.org/x/sys | v0.28.0 | 2024-12-03 | v0.47.0 | 2026-06-30 | only `x/sys/unix`, the syscall wrappers |

Versions and dates read from `https://proxy.golang.org/<module>/@latest` and
`.../@v/<version>.info` on 2026-08-15.

Two of those were badly out of date. `golang.org/x/sys` was twenty months old
and `golang.org/x/net` was nearly twenty. `github.com/google/nftables` was not
out of date at all, it simply has not had a release since February 2025, and
its own go.mod is what had been holding the others back.

### Known holes, and which ones the code can reach

Checked against the Go vulnerability database through
`https://api.osv.dev/v1/query` and `govulncheck`, both on 2026-08-15.

**The modules, before the update: nothing reachable.** This is the part worth
being precise about, because the raw advisory count for the old
`golang.org/x/net` looks alarming and is not.

- `golang.org/x/net` v0.33.0 had twelve advisories filed against it, plus
  three GitHub advisory records that are aliases of the same issues. Every one
  of them names `x/net/html`, `x/net/idna`, `x/net/http2`, `x/net/proxy`,
  `x/net/http/httpproxy` or `x/net/dns/dnsmessage`. **The only package of
  `x/net` in this binary is `x/net/bpf`**, which is on none of those lists.
  The link is broken at the package level, not argued about at the call level.
- `golang.org/x/sys` v0.28.0 had one, GO-2026-5024, in
  `golang.org/x/sys/windows`. The advisory's own record restricts it to
  `goos: windows`. The agent is Linux and uses `x/sys/unix`.
- `golang.org/x/sync` v0.6.0, `github.com/mdlayher/socket` v0.5.0,
  `github.com/mdlayher/netlink` at its pinned commit, and
  `github.com/google/nftables` v0.3.0: no advisories at all.

They were updated anyway. Being un-hit today is not a plan.

**The Go standard library, before the update: five, all reachable.** These are
the real finding. `govulncheck` traced each one to a call this binary makes:

| ID | What | Reached from |
|---|---|---|
| GO-2026-6218 | quadratic complexity in `net/url` `resolvePath` | `internal/report/client.go` sending the report |
| GO-2026-6090 | post-handshake message flood in `crypto/tls` | the same, over TLS |
| GO-2026-6088 | missing recursion depth guard in `encoding/xml` | `internal/collect/firewalld.go` parsing a zone file |
| GO-2026-5972 | missing recursion depth limit in `encoding/asn1` | certificate parsing during the TLS handshake |
| GO-2026-5026 | punycode label handling in the `x/net/idna` copy vendored inside `net/http` | the report client and the container collector |

All five are fixed in Go 1.26.6, published to the module proxy on 2026-08-11.
The agent was pinned to Go 1.26.5, published 2026-07-01. **`agent/go.mod` now
says `go 1.26.6`**, which
is what makes the toolchain refuse to build with an older, unpatched one, and
CI now takes its Go version from that file instead of from a separate number
in the workflow.

The one worth reading twice is GO-2026-5026. It is filed under the name
`golang.org/x/net/idna`, and it is easy to read that as "the module we pin is
vulnerable". It is not. The finding is against the copy of that code vendored
inside the standard library's `net/http`, which is why the fix is a Go release
and not a module bump. Confusing the two would have led to updating the wrong
thing and believing the problem was solved.

**After the update, `govulncheck` reports: `No vulnerabilities found.`**

### One observation with no fix

`github.com/google/nftables` v0.3.0 imports `github.com/mdlayher/netlink/nltest`
in production code, at `conn.go:27`, and exposes a `TestDial` field that
replaces the real netlink connection with a fake (`conn.go:38` and
`conn.go:306`). A test helper is therefore compiled into the shipped binary.

It does nothing here. The agent creates its connection with `nftables.New()`
and no options (`internal/collect/nftables_linux.go:33`), so `TestDial` is nil
and the fake is never dialled. It is written down because it is the sort of
thing that should be noticed rather than discovered later, and because it is a
point against this dependency if a replacement is ever considered.

## 2. The privilege question

This is the sharper half, and the honest answer is not the flattering one.

### What each read actually needs

Measured on Linux by running the agent with different capability sets and
reading which sections came back, rather than by reasoning from documentation.
The method is in "how this was measured" below.

| Read | Needs |
|---|---|
| `/proc/net/{tcp,tcp6,udp,udp6}`, the listening socket list | nothing at all |
| `/sys/class/net/*`, the overlay interfaces | nothing at all |
| mtimes of the rule files | nothing at all |
| the nf_tables ruleset over netlink | CAP_NET_ADMIN |
| legacy iptables and ip6tables over getsockopt | CAP_NET_RAW to open the socket, CAP_NET_ADMIN for the call, and only for a table the kernel lists in `/proc/net/ip_tables_names` (`ip6_tables_names`), which is 0440 root root. Asking about a table the kernel does not hold makes it load the table's module and create the table, so without the list no table is asked about (`internal/collect/iptables_present.go`) |
| `/etc/ufw/*` and `/etc/firewalld/*` contents | read permission on root-owned files |
| the Docker or Podman socket | root, or membership of the `docker` group |
| **naming the process that owns a port** | **CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE, both** |

The last line is the one that decides the answer.

### Measured: the socket list is free, naming the process is not

Running as an unprivileged user with no capabilities, the agent still returns
the complete list of listening ports. It gets zero process names.

Adding CAP_NET_ADMIN and CAP_NET_RAW brings back nftables, iptables and
ip6tables in full. Process attribution is still zero.

Adding CAP_DAC_READ_SEARCH: still zero. Adding CAP_SYS_PTRACE instead: still
zero. **Adding both together: full attribution.** `/proc/<pid>/fd` is mode
0500 owned by the process's own user, so the file mode has to be bypassed, and
the kernel applies a second, separate ptrace access check on top of it. One
capability defeats one gate. Both are needed for both.

### So can it stop being root? Yes, corrected 2026-08-19

**This section said no and it was wrong, because it never asked the right
question.** It measured the smallest capability set that reproduces *everything*
root produces, found that set includes CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE,
and concluded correctly that such a process is root in all but the uid column.
It then stopped, and never asked whether the *smaller* set could run
unprivileged.

It can. Measured with the shipped binary on 2026-08-19, `docs/RECORD.md` 4.64:
**a dedicated non-root user with CAP_NET_ADMIN and CAP_NET_RAW collects every
firewall layer, every port, every rule and every bind address.** Containers come
back with `docker` group membership. The only loss is the process name and pid
column.

**Re-measured across all three fleet hosts the same day, `docs/RECORD.md`
4.72, and the loss column above is wrong.** What survives everywhere is every
port, every bind address and **every live kernel rule**, over netlink. What is
additionally lost:

- **The intent files, on both distro families.** `/etc/ufw/user.rules` and
  `user6.rules` are 640 root root on Ubuntu 24.04, so the ufw rule list is
  empty non-root while its section header still reads collected.
  `/etc/firewalld` is 750 root root on AlmaLinux 10, so firewalld.conf and the
  admin zones are permission_denied. The intent-versus-kernel comparison the
  firewalld collector exists for stops working non-root on the distro family
  that runs firewalld.
- **Rootful podman containers.** The socket is root root 0660 and there is no
  docker-style group in the default install.

Both of those losses are recoverable with ordinary per-file read grants, and
that was measured, not proposed (`docs/RECORD.md` 4.72): with the docker group,
read ACLs on the ufw and firewalld files, and traversal plus read-write on
`/run/podman` and its socket, **the non-root document equals the root document
on both distro families except process names and timestamps**. A grant is one
visible line the operator can audit and revoke, scoped to one path, which no
capability can be.
- **Nothing new is lost for rootless podman**, because the rootful API does not
  list rootless containers even for root. The only signals are the listening
  socket, owned by the rootless network backend, and the uid column.

And the process name column is worth less than it looks. On a host where ssh is
socket-activated it reads `process_name: systemd, pid: 1`, because systemd owns
the listening socket. `systemctl show "*.socket" -p Listen` names the real unit
with no privilege at all, verified for TCP ports on three hosts (cockpit on
9090, ssh on 22).

**The packaged unit now ships this shape.** `User=whichports-agent`, a system
user the package creates, with `AmbientCapabilities` and
`CapabilityBoundingSet` both set to exactly CAP_NET_ADMIN and CAP_NET_RAW, and
CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE gone. The measurement it rests on is
`docs/RECORD.md` 4.72 above, the optional read grants that restore the intent
files are written out in `README.md`, and the clean-box suite asserts the
running process's uid and exact capability set from `/proc`, on both families,
on every change.

The original reasoning is kept below because it is right about the four
capability set, which is what it was measuring.

### The four capability set is root in all but name

The smallest capability set that reproduces what root produces is
**CAP_NET_ADMIN, CAP_NET_RAW, CAP_DAC_READ_SEARCH, CAP_SYS_PTRACE**.

That set is not a meaningful reduction. CAP_DAC_READ_SEARCH reads every file
on the machine regardless of permissions. CAP_SYS_PTRACE attaches to any
process, including root ones, and reads its memory. A process holding both is
root in everything but the number in the uid column, and presenting it as
"not running as root" would be a claim that sounds better than it is.

So the agent stays root, and this document says why rather than dressing it
up. What actually reduces the privilege is the sandbox, and that is where the
work went.

**There is a real reduction available and it is a product decision, not a code
one.** Drop CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE and the agent needs only
CAP_NET_ADMIN and CAP_NET_RAW, which are ordinary network administration
capabilities and nothing like root. The cost is exact and it is one thing: the
port list loses the process name and pid column. Everything else stays.
Whether that column is worth those two capabilities is the owner's call, not
this review's, and it is written up as a proposal below rather than done here.

### The unit takes away everything else

*This section describes the unit as reviewed on 2026-08-15, when it still ran
as root. The sandbox it describes is all still in place, and the unit has
changed twice since. The capability line and the user narrowed, see the
corrected section above. Two lines were then added that stop it executing
anything but the agent, see the last section below.*

The service unit was four hardening lines. It became the full set, and each
one has a reason next to it in the file. The capabilities above were the whole
of what root kept:

```
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
```

Everything else root normally carries is gone before the first instruction
runs. No loading modules, no mounting, no rebooting, no changing anyone's uid,
no binding a privileged port, no writing kernel tunables, no reading the
kernel log, no setting the clock or the hostname, no new namespaces. The
filesystem is read-only apart from one state directory, `/home` and `/root`
are empty to it, `/tmp` is its own, and the address families it may open are
limited to the four it uses. AF_PACKET is not among them, so despite holding
CAP_NET_RAW this process cannot see a packet.

Two of those settings are worth singling out.

**`SystemCallFilter=~@debug` was set even though CAP_SYS_PTRACE was held.** The
capability was needed only for the kernel's access check on `/proc/<pid>/fd`.
The `ptrace` system call itself is never used, so it was refused outright. The
capability that would let this process read another one's memory was held, and
the system call that would use it was blocked. The capability is gone now and
the filter stays.

**`ProtectProc` is deliberately left at default.** Hiding other processes would
silently empty the attribution column. It is the one setting not tightened,
and the unit says so in place rather than leaving a reviewer to wonder.

`systemd-analyze security` scored the old unit **8.9, "EXPOSED"** and the
hardened one **2.8, "OK"** on the same host. That is systemd's own number about
its own sandbox, quoted as measured. Both numbers are about the unit as it
stood on 2026-08-15, and neither of the two changes since has been re-scored,
so do not read 2.8 as today's number.

### How this was measured

Capability behaviour, in a Debian 12 container, using file capabilities so an
unprivileged user really holds them:

```sh
setcap cap_net_admin,cap_net_raw,cap_dac_read_search,cap_sys_ptrace=ep /usr/local/bin/whichports-agent
su -s /bin/sh -c 'whichports-agent --mode=stdout' nobody
```

The unit itself, under real systemd in a container running Ubuntu 24.04:
`systemctl start whichports-agent.service` finished with `Result=success`,
every section reported `collected`, all listening sockets kept their process
names, and the document was left `-rw-r----- root root`.

**What was not measured.** None of this ran on a physical host or on the
production box. It ran under a container's own network namespace, so the
rulesets read were the container's and not a real server's. The capability
gates are kernel behaviour and do not change between the two, but the claim
being made is about which capability lets which read succeed, not about any
particular host's rules. The unit should still be started once on a real box
before it is trusted on anyone else's.

### Where the sandbox does not hold: a systemd older than the setting

Added 2026-10-12 (`docs/RECORD.md` 4.220, 4.454). systemd starts a unit that
holds a setting it does not know, and leaves that setting out. So each line
of the sandbox holds only from the systemd release that brought it, and
nothing fails where a line is unknown.

**Measured on systemd 239, which Rocky Linux 8 ships.** The unit as it stands
in this repository, read by `systemd-analyze verify` in a container of Rocky
Linux 8.9 with `systemd-239-78.el8`, on 2026-10-12:

```
whichports-agent.service:64: Unknown lvalue 'ProtectProc' in section 'Service'
whichports-agent.service:72: Unknown lvalue 'ProtectKernelLogs' in section 'Service'
whichports-agent.service:74: Unknown lvalue 'ProtectClock' in section 'Service'
whichports-agent.service:75: Unknown lvalue 'ProtectHostname' in section 'Service'
whichports-agent.service:105: Unknown lvalue 'NoExecPaths' in section 'Service'
whichports-agent.service:106: Unknown lvalue 'ExecPaths' in section 'Service'
```

Those six and no other line. The journal of a Rocky Linux 8.10 test server
named the same six on 2026-09-30.

| setting | first release | what a systemd before it leaves out |
|---|---|---|
| `NoExecPaths=`, `ExecPaths=` | 248 | the refusal, at run time, to execute anything but the agent |
| `ProtectKernelLogs=` | 244 | the setting that keeps the process from the kernel log buffer |
| `ProtectClock=` | 245 | the setting that locks write access to the system clock |
| `ProtectHostname=` | 242 | the setting that stops the process changing the hostname |
| `ProtectProc=` | 247 | nothing: the unit sets it to `default` |

The releases are systemd's own, read on 2026-10-12: the `CHANGES WITH`
section of its `NEWS` file under which each setting is first named, and for
the last four the "Added in version" line of their entries in
`systemd.exec(5)`. `NEWS` under 248: "The ExecPaths= and NoExecPaths=
settings may be used to specify noexec for parts of the file system."

**The first row is the one that matters.** The second finding of the second
review, further down, is closed by those two lines: a raw system call
pointed at `execve` walks past the source scan, and the unit refuses it at
run time. On a systemd before 248 that refusal is not there. The code still
holds no call that executes anything and the scan still checks that on every
change, so what is lost is the second lock and not the first.

**What was not measured.** Whether the lines 239 does read keep the process
from the kernel log, the clock and the hostname by themselves. The unit runs
as its own user with two capabilities, and 239 reported neither `User=` nor
`CapabilityBoundingSet=` as unknown, but the unit was only read here and
never started under that systemd.

**There is no exposure number for such a host.** The 2.8 above is
`systemd-analyze security`, and `NEWS` names that verb first under 240:
"systemd-analyze also gained a new verb "security"". A systemd 239 host
cannot produce the number at all.

**The release number alone does not say what a host ignores.**
`RestrictSUIDSGID=` is first named under 242 and `systemd-239-78.el8` did not
report it as unknown, so that build knows it. What a given host leaves out is
read on that host, with the `verify` line at the top of this file.

## 3. The eight invariants, checked against the code

The project has eight, and `internal/safety` lists them. Each was traced to
source, and where the
source alone is not proof, measured.

**SI-1, no listening socket.** `strace -e trace=listen,bind` over a full run:
zero `listen()` calls. Two `bind()` calls, both on AF_NETLINK sockets, which
is how a netlink socket receives its replies and is not a listener. The whole
run opens four sockets: two AF_NETLINK for nf_tables, and one AF_INET and one
AF_INET6 raw socket used purely as handles for `getsockopt`, on which nothing
is ever sent or received. The source scan bans the calls that would open a
listener, and the ban list was widened in this review, see below. Holds.

*Added 2026-09-12.* A fifth socket since the unit column
(`internal/collect/sockdiag_linux.go`): one AF_NETLINK socket of protocol
NETLINK_SOCK_DIAG, never bound, on which four dump requests are sent and
their replies read, then closed. It is the address family the unit already
permits and needs no capability at all, measured with an empty set on two
hosts. The kernel accepts no write on that family. The trace above was not
re-run for it; the socket is a client socket by construction, the same shape
as the rtnetlink read in `interfaces.go`.

**SI-2, nothing acted on from a response.** `internal/report/client.go` reads
the status code, drains at most 4 KB of body into `io.Discard`, and parses
nothing. Enrollment involves no network at all. This was previously true by
inspection and by nobody having changed it. It is now enforced: a new test
fails the build if the report package imports any decoder, or calls
`io.ReadAll`, on the grounds that "there is no parser" is a much easier claim
to check than "the parser is careful". Holds.

**SI-3, read only.** No netlink message with a NEW, DEL, SET or FLUSH verb
appears anywhere. The nftables calls are `ListTables`, `ListChains` and
`GetRules`, all dumps. There is no `setsockopt`. The only writes the whole
binary performs are its own two files, the host document and the enrollment
config. When this was written that was a reading and nothing more, which is the
gap the second review named. The boundary scan now names every write method on
an `nftables.Conn` and fails the build if one is called, in the last section
below. Holds.

**SI-4, no exec.** `strace -e trace=execve,execveat` over a full run: the only
`execve` is the agent itself being started. No `os/exec` import, and the built
binary contains no `os.StartProcess`, `syscall.Exec` or `os/exec` symbol. The
scan that keeps it that way names the exec wrappers and cannot name the raw
syscall underneath them, so the packaged unit now refuses to execute anything
but the agent, in the last section below. Holds.

**SI-5, none of their credentials.** The only secret the agent stores is its
own, in `/etc/whichports/agent.conf`, owned by root with read for the agent's
own group and nothing for anyone else, and the loader refuses the file if it
is group-writable or accessible to others. On the directory above it, enroll
adds search for group and others and nothing else, so the agent's user can
reach the file whatever umask enroll ran under, and nobody gains read on
anything by it (docs/RECORD.md 4.201). No provider tokens, no SSH keys, no
code path that would use one. Holds.

**SI-6, authorised targets only.** The agent connects to two kinds of place
and no others: the local container runtime sockets, and the control plane URL
in its own config. It probes nothing. Holds.

**SI-7, no version detection.** Nothing sends a payload to any port or reads a
banner. What appears in the document is host state the host itself reports.
Holds.

**SI-8, typed telemetry.** Every section carries an enum status and an enum
cause. No error string reaches the document at any point, checked by grep for
`err.Error()` and error formatting into document fields, which returns
nothing. Error text goes to stderr and the journal, which stay on the machine.
Holds.

### A hole in the guard, which is the finding in this section

`internal/safety` states the boundary as a list in code and the tests scan the
source against it. Two things were wrong with that arrangement.

**The manifest was decorative.** `ForbiddenListenSymbols`,
`ForbiddenExecPackages` and `ForbiddenDialSymbols` were declared in
`safety.go` and **read by nothing**. The test kept its own second copy of the
list. Two lists of the same rules, one of them enforced and one of them the
one a reviewer would read, is precisely the drift this project has already
been bitten by. The tests now build their lookup from the manifest, so the
list in `safety.go` is the list that is enforced.

**The enforced list had gaps.** These would all have passed:

- `os.StartProcess`, which starts a program and needs no `os/exec` import, so
  the import check never saw it
- `net.ListenConfig`, `net.ListenUnix`, `net.FileListener` and four others,
  every one of which opens a listening socket without going through the three
  names that were banned
- `syscall.Listen` and `unix.Listen`, the raw call, which this agent is
  already close enough to the kernel to make
- `http.Serve` and `http.ServeTLS`
- importing `plugin`, which would let the binary load code that was not in the
  binary the operator inspected

All are now in the manifest and enforced.

**And the scanner itself was never tested.** A scan that matched nothing would
have passed every run while protecting nothing, and nobody would have found
out until after the boundary was crossed. There is now a test that feeds every
symbol in the manifest to the scanner inside source that really uses it, and
fails if any one is missed, plus one that checks clean source is not flagged.

## 4. Supply chain

### How a package gets built and signed

Packages are built by `nfpm` from one spec. Signing happens on the owner's
machine, with the private key exported from his keyring into a temp file that
a `trap` removes on exit, and a passphrase from the macOS keychain. The
private key is not in the repository and is not on any server. The public key
is committed and its fingerprint is published. `publish.sh` refuses to run on
a dirty tree or off `main`, so a published version always corresponds to a
commit. That is a sound arrangement and nothing here changes it.

### The finding: apt and dnf were not equally resistant to a key swap

`install.sh` fetched the signing key from `get.whichports.com` and pointed
each package manager at it. For apt that was already right: `signed-by=` names
a keyring file on local disk, and apt has no way to replace it from the
repository. Existing installs would reject packages signed with any other key.

The dnf branch wrote `gpgkey=https://get.whichports.com/...` into the repo
file, which is a URL and not a file. dnf's own documentation says of that
option:

> "If a file can not be verified using the already imported keys, import of
> keys from this option is attempted and the keys are then used for
> verification."

So on a host set up this way, an attacker who took over `get.whichports.com`
could serve packages signed with their own key, and dnf would go to the URL
they also control, fetch that key, and verify against it. Whether the operator
sees a prompt depends on how the update is run. The apt half of the same
installer had no such path. That asymmetry was not deliberate, it was two
branches written to look alike that behave differently.

**Fixed.** The installer now downloads the key once, writes it to
`/etc/pki/rpm-gpg/RPM-GPG-KEY-whichports`, and points `gpgkey=` at that local
file. Both package managers now verify against a copy on the operator's own
disk, and neither will accept a key rotation served by the repository.

**Also added, with a clear limit on what it buys.** The installer now checks
the fetched key's fingerprint against
`3EEDC9C6E4940A815D42CE43680A90826E2C982D` and installs nothing on a
mismatch. This catches a swapped key. It does **not** save anyone from a fully
compromised `get.whichports.com`, because the same host serves the installer,
and whoever changed the key could change the line that checks it. The
protection that survives that case is the previous paragraph: on a host that
is already installed, the key is on local disk and a new one is not accepted.
The script says all of this in its own comments, because someone reading
before piping it into a shell deserves the real picture.

### What a compromise of get.whichports.com would still get

Being straight about the residual risk:

- **New installs are trust on first use.** Anyone running `curl | sh` at the
  moment the host is compromised gets whatever it serves. The fingerprint
  check does not change that, and no `curl | sh` installer can. The honest
  mitigations are the ones already present: the script is short enough to read
  first, and it says so at the top.
- **Existing installs are covered against a key swap** and were already
  covered on the apt side.
- **An attacker who obtained the private signing key** defeats all of it. That
  key lives on one laptop and in a password manager, and it has no expiry
  date. An expiry would put a bound on how long a stolen key stays useful, and
  is proposed below.

## What was changed in this review

- `agent/go.mod` now requires Go 1.26.6, closing the five reachable standard
  library findings above.
- Five modules updated to current. `govulncheck` now reports nothing.
- CI takes its Go version from `go.mod` rather than a separate number, and
  runs `govulncheck` as a gate on every change.
- `internal/safety`: the manifest is now what the tests enforce, the ban list
  covers the ways round it listed above, and the scanner is itself tested.
- A new test enforces SI-2 mechanically: the report package may not import a
  decoder or read a response body into memory.
- The systemd unit is fully hardened, with the capability set measured rather
  than guessed, and the one setting left loose explained in place.
- The host document is written through `os.CreateTemp` rather than a fixed
  `.tmp` name. The old code, running as root, would have followed a symlink
  sitting at that name. The state directory is root-owned so nothing could
  place one there, which is why this is a hardening fix and not an incident,
  but "unreachable because of a directory's permissions" is a weaker thing to
  rest on than not following a link at all. The document is now written 0640
  rather than 0644, since it lists every listening port and the process behind
  it.
- The container collector reports a denied runtime socket as
  `permission_denied` instead of as a socket error. It was blaming the daemon
  for the agent's own lack of access.
- `install.sh`: the dnf key handling above, and the fingerprint check.
- `docs/PRODUCT.md` section 4e said the socket collector uses "the inet_diag
  netlink interface, `/proc/net` as fallback". Reading the code, there is no
  netlink in that collector at all and never has been. The document was
  corrected to what the code does. This changes nothing about privilege, since
  both routes need the same thing for the part that needs anything.

## What is accepted, and why

- **Root stays.** For the reasons in section 2. The set that would replace it
  is not meaningfully smaller.
- **`govulncheck` in CI fetches the tool at `@latest`.** That makes the CI run
  depend on whatever the Go team published, verified through the Go checksum
  database. Pinning it would make the run reproducible and the vulnerability
  tooling stale, which is the wrong trade for a check whose entire job is
  being current.
- **`nltest` in the shipped binary.** Explained in section 1. Unreachable in
  this use, and not worth forking a dependency over.
- **`github.com/google/nftables` has had no release since February 2025.** It
  is not out of date, but a quiet upstream is a thing to keep an eye on rather
  than a thing to be relaxed about. There is no alternative worth swapping to
  today, and writing the nf_tables netlink layer by hand would be a much
  larger surface than depending on this.

## What is proposed and not done

Each of these is a separate decision or a separate change, and putting them in
this review's diff would have made it too big to read.

1. **Decide whether the process name column is worth two capabilities.**
   Dropping CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE leaves the agent needing
   only CAP_NET_ADMIN and CAP_NET_RAW, which are ordinary and nothing like
   root. The cost is that the port list no longer says which process owns each
   port. This is the single largest privilege reduction available and it is a
   product call.
2. ~~**Three more places where a denied read is not reported as one.**~~
   **Closed on 2026-08-18, and two of the three were already closed before
   that.** Re-reading the code rather than the list: `firewalld.go` had gained
   a `denied` flag and returns permission denied, and `mtimes.go` had gained
   the rule that *any* denied stat escalates the section rather than only a
   run where every one was denied. Both cite `RECORD.md` 4.17.

   Two holes of the same shape did survive and are now fixed, with tests that
   fail against the old code:

   - `mtimes.go` discarded the error from listing the zone **directory**. A
     denied listing looked exactly like a host with no zone files: none were
     added, every static path stat succeeded, and the section said collected
   - `overlays.go` threw away the verdict from the tailscale state directory,
     so a permission error there came back as "not present" while the source
     still read collected

   The lesson worth keeping is about this document rather than the code: an
   item list in a review goes stale the moment somebody fixes something
   without editing it, and two of these three had been fixed for days while
   this file still called them open.
3. **Put an expiry on the package signing key.** It currently has none. An
   expiry bounds how long a stolen key is useful and forces a rotation drill
   before one is needed in anger.
4. **Start the hardened unit once on a real host** before it ships. It has
   been run under real systemd, but in a container.
5. ~~**`internal/collect/ufw.go` has no limit on the size of a file it
   reads.**~~ **Closed on 2026-08-18.** Both reads now go through
   `readCapped`, which stops at one megabyte, the same bound
   `firewalld.go` uses for a zone file.

   It **refuses** an oversized file rather than truncating it, which is the
   part worth stating: handing the key-value parser half a config would let it
   report a confident answer about a file it only partly saw, and for this
   product that is worse than a read that says it failed.

   Note what the bound does and does not do. The `io.LimitReader` bounds
   memory and no test can observe that without writing a file large enough to
   matter, so mutation testing correctly reports removing it as surviving. The
   length check is the half that changes an answer, and that one is tested.
6. **Branch protection on `main`.** `ONBOARDING.md` already notes that the
   local deny list is prefix matching and not a real guard. For a repository
   that builds a binary people install as root, the honest backstop is the
   one GitHub enforces.

## Four more findings, from a second review on 2026-08-22

A second review was briefed to break a claim in this document rather than walk
the eight invariants again. It failed to break SI-1 and SI-2 and said so with
evidence, which was the point. What it did break was the guard, and `#243`
carries that fix with `docs/RECORD.md` 4.95 behind it.

Four further findings came out of the same pass, each one its own change. All
four merged on 2026-08-22 and `docs/RECORD.md` `#259` records the day they
landed. They are written up here together, after the last of them landed rather
than one at a time, for the reason item 2 above gives: a list updated for one
item and not the next is worse than no list. Three of the four ship inside the
package, so they reach a host on a publish and not on a merge.

1. ~~**SI-3 had no mechanical enforcement at all.**~~ **Closed on 2026-08-22,
   by `#246`.** The boundary scan named the symbols that open a listening socket
   and the ones that start a program, and none that write a rule.
   `CollectNftablesLive` holds a live `*nftables.Conn`, and on that connection
   `FlushRuleset()` sits as close to the collector's code as the `ListTables()`
   it does call. The sandbox does not stand in the way, because the ruleset is
   written over netlink, which CAP_NET_ADMIN grants, while `ProtectSystem=strict`
   covers the filesystem.

   `internal/safety/safety.go` now carries `ForbiddenNftWriteSymbols`, 27 method
   names read from `go doc github.com/google/nftables` at v0.3.0, the version in
   `go.mod`. `TestNoNftablesWrites` fails the suite if any of them is called, and
   `TestScannerCatchesNftablesWrites` feeds every name in the manifest to the
   scanner inside source that really uses it, so this scan cannot quietly stop
   matching anything, which is the failure the section above found in the
   scanner that was never tested.

   It matches the bare method name on any receiver, which is blunter than the
   package-qualified call scan and deliberately so. A method call carries no
   package qualifier and an AST scan does not know a variable's type, so a
   `Conn` handed out by a helper reaches a file that never imports nftables, and
   matching the name closes that.

   What it does not reach is a message built by hand and sent through
   `github.com/mdlayher/netlink`, which is in the binary as a transitive
   dependency and which nothing here imports directly. Banning that import
   outside the one collector file is the same shape as `HTTPCapableFiles`, and
   it is on the board rather than folded into `#246`.

2. ~~**`unix.Syscall` and `unix.Syscall6` cannot be put on the exec ban
   list.**~~ **Closed on 2026-08-22, by `#253`.** The ban names ten wrappers,
   `exec.Command` and `os.StartProcess` and `syscall.Exec` among them. It cannot
   name the raw gateway under them, because `internal/collect/iptables_linux.go`
   legitimately calls `unix.Syscall6(unix.SYS_GETSOCKOPT, ...)` to read the
   legacy x_tables ruleset. A `Syscall6` pointed at `SYS_EXECVE` walks past the
   scan, so the answer had to be a runtime one rather than another list entry.

   The unit now carries two lines:

   ```
   NoExecPaths=/
   ExecPaths=/usr/bin/whichports-agent
   ```

   `NoExecPaths=` marks the whole tree non-executable and `ExecPaths=` gives back
   the one binary systemd still has to be able to run. The kernel then refuses to
   execute anything else whichever call asked, a raw syscall included. Both
   options are quoted from `systemd.exec(5)` in the unit's own comment. One
   `ExecPaths` entry is the whole list because the binary is a static
   `CGO_ENABLED=0` build with no dynamic loader and no shared library.

   Both lines need systemd 248 or newer. An older one ignores them and
   starts the unit without the refusal, which is measured on systemd 239 in
   "Where the sandbox does not hold" above.

   It does not overlap `MemoryDenyWriteExecute=yes`, which the 2026-08-15 unit
   already had. That one denies a mapping that is writable and executable at
   once, the shape a JIT needs. This one denies executable mappings of files by
   path, so a plain `execve` of `/bin/sh` is allowed by the first and refused by
   the second.

   `agent/ops/cleanbox` asserts both halves on real systemd, in a container on
   both distro families, and CI runs that suite on Linux on every change under
   `agent/`. A drop-in setting `ExecStart=/usr/bin/true` under the shipped unit
   fails to start with `ExecMainStatus=203`, systemd's EXIT_EXEC, and the same
   command with the two lines cleared starts and exits 0. The second half is
   what stops the first from passing for some other reason.

   Two limits are worth stating plainly. It covers `execve` of a file on the real
   filesystem, which is the finding's threat, and not `PrivateTmp`'s own `/tmp`
   bind, `/dev/shm` or `memfd_create`, each of which needs its own setting and
   its own proof and is on the board. And it is a property of the packaged unit,
   so a `--mode=oneshot` run from cron or Ansible has none of this sandbox and
   the source scan is all that stands there.

3. ~~**`postinstall.sh` chowned through a symlink as root.**~~ **Closed on
   2026-08-22, by `#247`.** The scriptlet chowned `/var/lib/whichports` and,
   when one exists, `/etc/whichports/agent.conf`. Both `chown` and `chmod`
   follow a link to whatever it points at, so a link planted at either path had
   this script, running as root during package configure, hand ownership of an
   arbitrary file to the agent user. It was reproduced on the real .deb.

   Each path is now tested with `[ -L ... ]` first and the script exits 1 rather
   than skipping quietly, because a link sitting there means somebody rearranged
   the host and that is the operator's to look at. Both chowns also carry
   `--no-dereference`, so the chown itself cannot cross a link even one that
   appears after the check. `chmod` has no equivalent flag, so for the two chmods
   the check is the only guard and the script says so in place. `preremove`,
   `postremove` and the uninstaller were read and hold no ownership operation,
   and there is no `preinstall`.

   Planting the link needs root already, which is why this is hardening and not
   an incident. The argument is the one `writeFileAtomic` in `cmd/agent/main.go`
   already makes in writing, and which the temp-file change above rests on too:
   "unreachable given the directory permissions" is a weaker thing to rely on
   than not following a link at all.

4. ~~**The unit symlink escape guard was one hop deep.**~~ **Closed on
   2026-08-22, by `#248`.** The guard in `internal/collect/socketunits.go` kept a
   unit-file symlink inside the unit directories, but it read a single link with
   `os.Readlink`. A two-hop chain whose first link landed back inside a unit
   directory passed the check while its second link pointed at any file on the
   host. `os.Open` follows every hop, so the collector read that file and put its
   `Description=` line in the document, which then went to the control plane,
   with nothing marked incomplete.

   `unitSymlinkRefused` now resolves the whole chain with
   `filepath.EvalSymlinks` and requires the real path at the end to be
   `/dev/null`, which is how systemd masks a unit, or to be inside the unit
   directories. Each unit directory is resolved the same way before the
   comparison, so a symlink in the root path itself, macOS `/var` to
   `/private/var`, is not misread as an escape. A chain that resolves to nothing,
   a loop or a dangling link, is refused too, because there is no real file at
   the end to bound-check and letting the later `os.Open` chase the same chain is
   what this exists to stop.

   No new field was invented for it. Every refusal carries the
   `symlink_outside_unit_directories` marker the one-hop guard already used, and
   the enum's comment in `hostdoc.go` now says it covers the chain cases as well,
   so the one document-visible fact stayed in one place.

   What is left is narrow and named here rather than left for a reader to find.
   The guard resolves the path and `readCapped` opens it again a moment later, so
   the check and the open are two separate resolutions of the same path. Swapping
   the chain in between needs write access to a unit directory, which means root
   on any host that installs this.
