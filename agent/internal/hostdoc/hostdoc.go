// Package hostdoc defines the host document: the single JSON object the agent
// produces per host per run. It is the contract every downstream part depends
// on, so it is deliberately small, versioned, and free of any conclusion.
//
// Design decisions are recorded in docs/PRODUCT.md section 4e. The ones the
// types here enforce:
//
//   - The document reports evidence, never a verdict. There is no reachability
//     field, no attribution, no severity. The control plane draws conclusions.
//   - Every section carries its own status, so one failed read never empties
//     the document. A permission error on nftables must not lose the sockets.
//   - Statuses and error causes are typed enums, never free text, so nothing
//     the host says leaks across the wire as an untyped string (SI-8).
//   - IPv4 and IPv6 are always distinct. A value is measured or marked not
//     collected, never inferred from the other family.
package hostdoc

// SchemaVersion is the version of the document envelope. It only ever
// increases, and changes are additive: downstream code keyed to version 1 must
// keep working when version 2 adds fields. A breaking change is a new major.
const SchemaVersion = 1

// SectionStatus is the outcome of collecting one section. It is an enum so the
// wire format never carries a free-text error (SI-8). A section that fails
// still appears in the document with a status other than Collected.
type SectionStatus string

const (
	// StatusCollected means the section was read successfully.
	StatusCollected SectionStatus = "collected"
	// StatusNotPresent means the source does not exist on this host, for
	// example ufw on a box that has never installed it. Not an error.
	StatusNotPresent SectionStatus = "not_present"
	// StatusPermissionDenied means the read needed a privilege the agent did
	// not have. Actionable, and distinct from the source being absent.
	StatusPermissionDenied SectionStatus = "permission_denied"
	// StatusReadError means the source existed but could not be read or parsed.
	// The detail is a typed cause, never the raw error string.
	StatusReadError SectionStatus = "read_error"
	// StatusNotCollected means this build or this run did not attempt the
	// section. It is the honest value behind "not tested" (PRODUCT.md 4b).
	StatusNotCollected SectionStatus = "not_collected"
)

// valid reports whether s is a defined status. Used by the tests to guarantee
// no section ever ships an unknown status, and by MarshalHostDocument to fail
// closed rather than emit an unknown value.
func (s SectionStatus) valid() bool {
	switch s {
	case StatusCollected, StatusNotPresent, StatusPermissionDenied,
		StatusReadError, StatusNotCollected:
		return true
	}
	return false
}

// ErrorCause is a typed reason a section did not fully collect. It travels in
// place of any raw error text, so operating-system error strings, which can
// contain paths or other host detail, never cross the wire (SI-8).
type ErrorCause string

const (
	CauseNone            ErrorCause = ""
	CausePermission      ErrorCause = "permission"
	CauseSourceMissing   ErrorCause = "source_missing"
	CauseParseFailed     ErrorCause = "parse_failed"
	CauseTimeout         ErrorCause = "timeout"
	CauseUnsupportedKern ErrorCause = "unsupported_kernel"
	// CauseNetlink means a netlink conversation with the kernel failed for a
	// reason other than permission. The failing operation's error text stays
	// on the host (SI-8).
	CauseNetlink ErrorCause = "netlink"
	// CauseSocketError means a local socket existed but the conversation over
	// it failed, for example a stale runtime socket with no daemon behind it.
	// Distinct from timeout, which means the daemon answered too slowly.
	CauseSocketError ErrorCause = "socket_error"
)

// valid reports whether c is a defined cause.
func (c ErrorCause) valid() bool {
	switch c {
	case CauseNone, CausePermission, CauseSourceMissing, CauseParseFailed,
		CauseTimeout, CauseUnsupportedKern, CauseNetlink, CauseSocketError:
		return true
	}
	return false
}

// Section is embedded in every collected section. It records how the read went
// so a partial document is still honest about what is missing and why.
type Section struct {
	Status SectionStatus `json:"status"`
	// Cause is set only when Status is a failure. It is CauseNone otherwise.
	Cause ErrorCause `json:"cause,omitempty"`
}

// Document is one host's evidence for one run. Fields are added over time; the
// envelope is what is stable. Sockets is a pointer so "not collected" (nil) is
// distinguishable from "collected, and empty" (non-nil, zero length).
type Document struct {
	SchemaVersion int    `json:"schema_version"`
	Hostname      string `json:"hostname"`
	// AgentVersion is the package version of the binary that produced this
	// document, the same string --version prints and the same one nfpm
	// stamps on the .deb and .rpm. Added 2026-08-22 under the additive rule
	// (PRODUCT.md 4e principle 1): a reader keyed to a document without it
	// keeps working, because the field is simply absent.
	//
	// It exists because the fleet was upgraded 0.1.5 to 0.1.6 and nothing in
	// the product could confirm it. Every host had to be reached over ssh to
	// answer a question about the hosts (docs/RECORD.md 4.89). A plain
	// `go build` leaves it empty and the field is omitted rather than
	// guessed, which is the same posture --version takes.
	AgentVersion string `json:"agent_version,omitempty"`
	// CollectedAtUnix is set by the caller, never by this package, because the
	// clock is a side effect and this package stays pure so it can be tested
	// deterministically.
	CollectedAtUnix int64 `json:"collected_at_unix"`

	Sockets *SocketsSection `json:"sockets,omitempty"`
	// SocketUnits is what systemd's socket unit files declare, which is how a
	// port systemd itself holds gets attributed to the unit that serves it.
	// Added 2026-08-19 under the same additive rule as the section below.
	SocketUnits *SocketUnitsSection `json:"socket_units,omitempty"`
	// InterfaceAddresses is which addresses the host holds, as distinct from
	// which addresses something is listening on. Added 2026-08-17 under the
	// additive rule (PRODUCT.md 4e principle 1): a reader keyed to the
	// document without it keeps working, because the field is simply absent.
	InterfaceAddresses *InterfaceAddressesSection `json:"interface_addresses,omitempty"`
	Nftables           *NftablesSection           `json:"nftables,omitempty"`
	Ufw                *UfwSection                `json:"ufw,omitempty"`
	Firewalld          *FirewalldSection          `json:"firewalld,omitempty"`
	RuleFiles          *RuleFilesSection          `json:"rule_files,omitempty"`
	Containers         *ContainersSection         `json:"containers,omitempty"`
	// Iptables and Ip6tables are the legacy x_tables rulesets, two separate
	// sections because they are two separate rule sets and a rule written
	// for one does not apply to the other (PRODUCT.md 4, 4b).
	Iptables  *IptablesSection `json:"iptables,omitempty"`
	Ip6tables *IptablesSection `json:"ip6tables,omitempty"`
	Overlays  *OverlaysSection `json:"overlays,omitempty"`
	// Packages is what dpkg's records say about the program behind each
	// service with a listening socket (packages.go).
	Packages *PackagesSection `json:"packages,omitempty"`
}

// OverlaysSection is the identity evidence for overlay networking: what kind
// each interface is, and whether an overlay daemon is present. The overlays'
// firewall chains arrive verbatim in the kernel sections; WireGuard adds no
// chains at all, so interface identity is its only trace.
type OverlaysSection struct {
	Section
	// Sources carries one verdict per check, keyed by OverlaySources.
	Sources    map[string]Section `json:"sources,omitempty"`
	Interfaces []OverlayInterface `json:"interfaces,omitempty"`
	// Tailscale and Netbird report daemon presence. A false is a measured
	// answer, not an omission, which is why these are always present.
	Tailscale *OverlayPresence `json:"tailscale,omitempty"`
	Netbird   *OverlayPresence `json:"netbird,omitempty"`
}

// OverlaySources are the only keys allowed in OverlaysSection.Sources.
var OverlaySources = []string{"interfaces", "tailscale", "netbird"}

// OverlayInterface is one network interface's identity evidence, all read
// from sysfs: Type is the ARPHRD number as the kernel prints it, DevType is
// the driver's device type when one is set ("wireguard", "bridge"), and Tun
// marks the tun driver's sysfs signature.
type OverlayInterface struct {
	Name    string `json:"name"`
	Type    string `json:"type,omitempty"`
	DevType string `json:"devtype,omitempty"`
	Tun     bool   `json:"tun,omitempty"`
}

// OverlayPresence is one daemon's presence evidence.
type OverlayPresence struct {
	Socket   bool `json:"socket"`
	StateDir bool `json:"state_dir,omitempty"`
}

// IptablesSection is one legacy x_tables ruleset (v4 or v6), read through
// the kernel's getsockopt interface. On an iptables-nft host these tables
// are empty or absent, and the nftables section is where those rules live.
type IptablesSection struct {
	Section
	// Sources carries one verdict per kernel table, keyed by IptTables.
	Sources map[string]Section `json:"sources,omitempty"`
	Tables  []IptTable         `json:"tables,omitempty"`
}

// IptTables are the only keys allowed in IptablesSection.Sources.
var IptTables = []string{"filter", "nat", "mangle", "raw", "security"}

// IptTable is one table that exists on the host.
type IptTable struct {
	Name   string     `json:"name"`
	Chains []IptChain `json:"chains,omitempty"`
}

// IptChain is one chain. Builtins carry a policy; user chains do not. Rule
// order is evaluation order, preserved exactly.
type IptChain struct {
	Name    string `json:"name"`
	BuiltIn bool   `json:"builtin,omitempty"`
	// Policy is "accept" or "drop", empty for user chains.
	Policy string    `json:"policy,omitempty"`
	Rules  []IptRule `json:"rules,omitempty"`
}

// IptRule is one rule, rebuilt into iptables' own option vocabulary with the
// same honesty grade the nftables renderer uses: full, partial or none.
type IptRule struct {
	Text     string `json:"text"`
	Rendered string `json:"rendered"`
}

// ContainersSection is what the container runtimes report over their local
// sockets: running containers and the ports they publish. Docker and Podman
// are separate lists because the two publish through different mechanisms
// and behave differently against a host firewall (PRODUCT.md 4, 4d); merging
// them would erase exactly the distinction the product exists to show.
type ContainersSection struct {
	Section
	// Sources carries one verdict per runtime socket, keyed by
	// ContainerSources. A missing socket is not_present, the normal state.
	Sources map[string]Section `json:"sources,omitempty"`
	Docker  []Container        `json:"docker,omitempty"`
	Podman  []Container        `json:"podman,omitempty"`
}

// ContainerSources are the only keys allowed in ContainersSection.Sources.
var ContainerSources = []string{"docker", "podman"}

// Container is one running container, identity sanitized, with its published
// ports. A container publishing nothing still appears: it exists, and that
// is evidence.
type Container struct {
	ID    string          `json:"id"`
	Name  string          `json:"name,omitempty"`
	Image string          `json:"image,omitempty"`
	Ports []PublishedPort `json:"ports,omitempty"`
}

// PublishedPort is one host-side publication: traffic to HostIP:HostPort is
// forwarded to the container's ContainerPort. HostIP is what the runtime
// reported, verbatim; empty means the runtime did not say.
type PublishedPort struct {
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// RuleFilesSection is when each known firewall configuration file last
// changed, by stat. It exists so "when did this change" has an answer before
// any history exists (PRODUCT.md 4). Files that do not exist on the host are
// absent from the list; an empty list on a host with none of the tools
// installed is a measured answer.
type RuleFilesSection struct {
	Section
	Files []RuleFileStat `json:"files,omitempty"`
}

// RuleFileStat is one existing rule file. Path is absolute as the host knows
// it, and MtimeUnix is the file's modification time.
type RuleFileStat struct {
	Path      string `json:"path"`
	MtimeUnix int64  `json:"mtime_unix"`
}

// SocketsSection lists the listening sockets found on the host. It is the first
// collector (board card M1). Bind address and owning process are what make a
// socket meaningful, so both are carried per entry.
type SocketsSection struct {
	Section
	// Sources records how each individual source file read went, keyed by the
	// names in SocketSources. It exists because the section-level status alone
	// can hide a partial failure: tcp parsing while tcp6 is unreadable must
	// not look like "v6 measured and empty" (PRODUCT.md 4b). A reader that
	// wants to trust a family checks the family's sources, not just the
	// section. Additive since 2026-08-12, RECORD.md 4.15.
	Sources   map[string]Section `json:"sources,omitempty"`
	Listening []ListeningSocket  `json:"listening"`
}

// SocketSources are the only keys allowed in SocketsSection.Sources. The
// marshaller fails closed on anything else, the same posture as the enums.
// "passwd" is the owner-name lookup file, not a socket table: its verdict is
// carried so an unreadable passwd is distinguishable from a passwd that does
// not name the uids, because a refusal reported as an absence is the wrong
// answer this project keeps re-finding (denied_reads_test.go). It never
// decides the section status, which stays the four socket tables' alone.
var SocketSources = []string{"tcp", "tcp6", "udp", "udp6", "passwd",
	"sock_diag", "cgroup2"}

// MaxCgroupPathLen bounds ListeningSocket.Cgroup in bytes. A cgroup path is a
// path on the cgroup2 filesystem and PATH_MAX is 4096 on Linux
// (include/uapi/linux/limits.h, read at v6.8 on 2026-09-12), so a longer
// string was never a path the kernel handed out.
const MaxCgroupPathLen = 4096

// MaxOwnerNameLen bounds ListeningSocket.OwnerName in bytes. glibc caps a
// login name at LOGIN_NAME_MAX, which is 256 (bits/local_lim.h and
// getconf LOGIN_NAME_MAX, both read on Debian glibc on 2026-08-19), so a
// longer string in the passwd file is not a login name this document will
// print. The collector enforces it by leaving the name empty, the uid stays,
// and the marshaller fails closed if code ever bypasses that.
const MaxOwnerNameLen = 256

// ListeningSocket is one listening endpoint. Family is kept explicit rather
// than inferred from the address text, because v4 and v6 must never be guessed
// from each other (PRODUCT.md 4b).
type ListeningSocket struct {
	// Protocol is "tcp" or "udp".
	Protocol string `json:"protocol"`
	// Family is "v4" or "v6".
	Family string `json:"family"`
	// BindAddress is the local address as the kernel reports it, verbatim.
	BindAddress string `json:"bind_address"`
	Port        int    `json:"port"`
	// ProcessName is the owning process comm, empty if attribution was not
	// possible (which is itself information: a socket we cannot attribute).
	ProcessName string `json:"process_name,omitempty"`
	// PID is 0 when unknown, for the same reason.
	PID int `json:"pid,omitempty"`
	// OwnerUID is the socket's owning uid, read from the same /proc/net row
	// as the socket itself. Under a non-root agent the process name above is
	// unreadable and this column is the free signal that still names an
	// owner, measured across the fleet on 2026-08-19 (docs/RECORD.md 4.64).
	// A pointer, because uid 0 is root and a real answer: nil means the
	// row's uid field did not parse, never "probably root". Added 2026-08-19
	// under the additive rule (PRODUCT.md 4e principle 1), so documents from
	// older agents simply lack the field.
	OwnerUID *int64 `json:"owner_uid,omitempty"`
	// OwnerName is the name the host's own passwd file gives OwnerUID,
	// sanitized, empty when the file does not name it. The uid is the
	// measurement and this is a lookup of it in what the host itself says,
	// never a guess (PRODUCT.md 4b): a uid the file does not know keeps the
	// number and no name.
	OwnerName string `json:"owner_name,omitempty"`
	// Cgroup is the cgroup2 path of the socket's owner as the kernel reports
	// it over sock_diag netlink (INET_DIAG_CGROUP_ID, Linux 5.8 and newer),
	// resolved against the cgroup2 mount, e.g. "/system.slice/caddy.service".
	// It costs no capability, measured on three hosts with an empty set
	// (docs/AGENT-PRIVILEGE.md 4a). Empty when the kernel sent no id, when the
	// id matched no directory, or when the host has no cgroup2 mount: absent
	// means not named, never "probably nothing". Added 2026-09-12 under the
	// additive rule (PRODUCT.md 4e principle 1).
	Cgroup string `json:"cgroup,omitempty"`
	// Unit is the systemd unit the cgroup path ends in, when it ends in one:
	// the last path element if it is a .service, .socket, .scope or .slice.
	// A Docker published port reads docker.service here, and the container
	// is named by the containers section, not by this. A rootless container
	// or a login session reads a scope, which names a session and not a
	// service, and is carried as what the kernel said. A lookup of Cgroup,
	// never a guess: empty whenever Cgroup is empty or its last element is
	// not a unit.
	Unit string `json:"unit,omitempty"`
}

// SocketUnitsSection is what systemd's *.socket unit files declare: the
// addresses a socket unit asks the manager to listen on, and the service unit
// that gets the socket when traffic arrives.
//
// It exists because a socket-activated port has no useful owning process. The
// manager holds the listening socket and passes it on, so the sockets section
// reports port 22 as "systemd" pid 1 on a host where ssh is socket activated,
// which names nothing (RECORD.md 4.64). Under an unprivileged agent there is
// no process name at all (RECORD.md 4.72). The unit files are world readable
// on both distro families measured, so this attribution costs no privilege.
//
// **It is declaration, not measurement.** A unit file naming port 22 does not
// mean anything is listening on port 22. Nothing here says a port is open, and
// joining a declared address to a measured listening socket is the control
// plane's job, exactly as it is for firewalld's zones against the kernel's
// ruleset. Enablement (a symlink in a .wants directory), being active, and
// listening are three different facts, and this section reports only the first
// of them, because that is the only one a file read can answer.
type SocketUnitsSection struct {
	Section
	// Sources carries one verdict per unit directory, keyed by
	// SocketUnitSources.
	Sources map[string]Section `json:"sources,omitempty"`
	// TypeDropIns are drop-in files that apply to every socket unit on this
	// host, from the top-level socket.d directories. They are listed here
	// once rather than repeated on every unit.
	//
	// Not tidiness. Repeating them made the document grow as the square of
	// the host. Measured 2026-08-21: 10 units with 10 such drop-ins gave
	// 7.3 KB, 50 with 50 gave 116 KB, and 200 with 200 gave 1.7 MB. The agent
	// posts this on a timer, so that is a cost a host imposes on the control
	// plane merely by having many units.
	//
	// Each unit still carries "drop_ins" in Incomplete, because these do
	// apply to it and its address list may not be the whole answer.
	TypeDropIns []string `json:"type_drop_ins,omitempty"`
	// Units is every *.socket file found, in the order the directories are
	// searched. A unit file present in two directories appears twice: which
	// one systemd loads follows from the order (systemd.unit(5), UNIT FILE
	// LOAD PATH), and applying that rule is a conclusion, which belongs to
	// the control plane the same way firewalld's /etc-over-vendor override
	// does.
	Units []SocketUnit `json:"units,omitempty"`
}

// SocketUnitSources are the only keys allowed in SocketUnitsSection.Sources,
// listed in systemd's own load-path precedence order.
var SocketUnitSources = []string{
	"run_systemd_generator_early",
	"etc_systemd_system",
	"run_systemd_system",
	"run_systemd_generator",
	"usr_local_lib_systemd_system",
	"usr_lib_systemd_system",
	"run_systemd_generator_late",
}

// SocketUnitOrigins are the only values SocketUnit.Origin takes. The manual's
// load-path table calls /etc/systemd/system and /usr/local/lib/systemd/system
// administrator directories, /run/systemd/system runtime, and
// /usr/lib/systemd/system the package manager's. "generator" is the three
// generator directories, whose units a generator writes at boot.
var SocketUnitOrigins = []string{"admin", "runtime", "vendor", "generator"}

// SocketUnitListenDirectives are the only values SocketUnitListen.Directive
// takes: every Listen* option systemd.socket(5) defines. The five that cannot
// be an internet socket are here because a unit declaring one is not a unit
// declaring nothing, and dropping them made fifteen real units across the
// fleet read as empty.
var SocketUnitListenDirectives = []string{
	"ListenStream",
	"ListenDatagram",
	"ListenSequentialPacket",
	"ListenFIFO",
	"ListenSpecial",
	"ListenNetlink",
	"ListenMessageQueue",
	"ListenUSBFunction",
}

// SocketUnitServiceSources are the only values SocketUnit.ServiceSource takes.
// The distinction is the point of the field: "declared" means the file said
// Service=, "implied" means we applied the manual's default rule, "unknown"
// means we could not tell which rule applies.
var SocketUnitServiceSources = []string{"declared", "implied", "unknown"}

// SocketUnitIncompleteReasons are the only values allowed in
// SocketUnit.Incomplete. Each one says "the listen list below may not be what
// systemd computed", and each is typed rather than free text (SI-8).
var SocketUnitIncompleteReasons = []string{
	// drop_ins: *.socket.d/*.conf files exist for this unit and this
	// collector does not merge them.
	"drop_ins",
	// listen_reset_undocumented: an empty assignment to a Listen directive
	// whose reset behaviour the manual we read does not describe.
	"listen_reset_undocumented",
	// repeated_directive: a single-valued directive is assigned more than
	// once and the manual we read does not say which assignment wins.
	"repeated_directive",
	// description_truncated: Description= was longer than the collector will
	// put on the wire and was cut. The host chooses that text, so its length
	// is not ours to trust (SI-8 keeps free text off the wire, and this is
	// the one field the manual makes free text by design).
	"description_truncated",
	// symlink_outside_unit_directories: the unit file is a symlink that does
	// not resolve to a unit file inside the unit directories, so it was not
	// opened. systemd links units to /dev/null to mask and to other unit files
	// to alias or enable, and all of those resolve to /dev/null or stay inside
	// the unit directories. The whole chain is resolved, so this also covers a
	// chain whose last hop points out of the tree, and a chain that loops or
	// dangles and reaches no real file to bound-check. Following any of them
	// would let the agent read a file nobody chose for it.
	"symlink_outside_unit_directories",
}

// SocketUnit is one *.socket file, as read.
type SocketUnit struct {
	// Name is the unit name, which is the file name: "ssh.socket".
	Name string `json:"name"`
	// File is the absolute path the unit was read from, as the host knows it.
	File string `json:"file"`
	// Origin is one of SocketUnitOrigins.
	Origin string `json:"origin"`
	// Template is true when the name ends in "@.socket". A template is the
	// pattern instances are made from and is not itself a listener
	// (systemd.unit(5)): its addresses can carry an unresolved "%i", and the
	// instances live in the manager's runtime state, which is not a file.
	Template bool `json:"template,omitempty"`
	// Masked is true for a zero-length file or a symlink to /dev/null, which
	// systemd does not load at all (systemd.unit(5)). Nothing else in the
	// entry is meaningful when it is set.
	Masked bool `json:"masked,omitempty"`
	// AliasOf is the unit this file is a symbolic link to, when it points at
	// another unit rather than at /dev/null. systemd treats such a link as
	// another name for the same unit, not as a second unit.
	//
	// When this is set the entry carries no Listen list and no service name.
	// Repeating them counted one real port twice, and implying a service from
	// the link's own name produced a service that does not exist: a link
	// called alias.socket was reported as starting alias.service.
	AliasOf string `json:"alias_of,omitempty"`
	// Instance is the instance name when this entry is a template instance
	// enabled by a symlink, for example "7006" for inst@7006.socket. File
	// then points at the template the instance is made from, because that is
	// the file systemd reads.
	//
	// Such an instance has no file of its own, so an earlier version dropped
	// it entirely and a listening port disappeared: a
	// sockets.target.wants/inst@7006.socket link over a template declaring
	// ListenStream=%i is port 7006, enabled, and was absent from the
	// document.
	Instance string `json:"instance,omitempty"`
	// Source is the key of the directory this file came from, matching
	// SocketUnitsSection.Sources. Origin cannot rank two directories that
	// share it, and /etc/systemd/system and /usr/local/lib/systemd/system are
	// both "admin", so a reader deciding which copy systemd loads needs this
	// rather than the order of the array.
	Source string `json:"source"`
	// Parsed is false when the file existed but was not read or understood,
	// in which case only Name, File, Origin and Masked mean anything. Same
	// posture as FirewalldZone.Parsed.
	Parsed bool `json:"parsed"`
	// SocketSection is whether a [Socket] section was present. systemd
	// requires one (systemd.socket(5)), so false is a finding about the file
	// rather than about this read.
	SocketSection bool `json:"socket_section"`
	// Description is the unit's [Unit] Description=, verbatim and sanitized.
	Description string `json:"description,omitempty"`
	// Listen is the ListenStream= and ListenDatagram= entries in file order,
	// which is the order systemd passes them to the service.
	Listen []SocketUnitListen `json:"listen,omitempty"`
	// ListenReset records that an empty assignment reset the address list
	// somewhere in the file, so entries written above it were discarded
	// (systemd.socket(5)). The list here already honours it.
	ListenReset bool `json:"listen_reset,omitempty"`
	// ServiceUnit is the service unit that gets the socket, and
	// ServiceSource says whether the file stated it or we derived it.
	ServiceUnit   string `json:"service_unit,omitempty"`
	ServiceSource string `json:"service_source,omitempty"`
	// Accept and BindIPv6Only are those two directives verbatim, empty when
	// the file did not set them. BindIPv6Only is here because it decides
	// whether a socket bound to an IPv6 address also answers on IPv4, and
	// that is not something this collector may conclude for itself.
	Accept       string `json:"accept,omitempty"`
	BindIPv6Only string `json:"bind_ipv6_only,omitempty"`
	// DropIns are the *.conf drop-in paths found for this unit, sorted. They
	// are reported and not merged, so Incomplete carries "drop_ins" whenever
	// this is non-empty.
	DropIns []string `json:"drop_ins,omitempty"`
	// EnableLinks are symlinks to this unit name found in .wants or
	// .requires directories, which is how enablement is recorded on disk
	// (systemd.unit(5)). A link means something asked for this unit, not
	// that the unit is running and not that a port is open.
	EnableLinks []string `json:"enable_links,omitempty"`
	// Incomplete holds reasons from SocketUnitIncompleteReasons. Non-empty
	// means the Listen list may differ from what systemd computed, and a
	// reader must not treat it as the whole answer.
	Incomplete []string `json:"incomplete,omitempty"`
}

// SocketUnitKinds are the only values SocketUnitListen.Kind takes, one per
// address form systemd.socket(5) documents for ListenStream=, plus two for
// what this collector refuses to interpret.
var SocketUnitKinds = []string{
	// port_only is a bare number: "ListenStream=9090". It specifies a port
	// and no address at all.
	"port_only",
	"ipv4",
	"ipv6",
	"unix_path",
	"unix_abstract",
	"vsock",
	// specifier is a value carrying a "%" specifier we do not expand, for
	// example "%i" in a template.
	"specifier",
	// not_an_internet_socket is a listener that cannot be a TCP or UDP port
	// at all: ListenFIFO=, ListenSpecial=, ListenNetlink=,
	// ListenMessageQueue=, ListenUSBFunction= and ListenSequentialPacket=.
	// It carries no port, no address and no family, because it has none.
	//
	// It is recorded rather than dropped: a unit declaring one is not a unit
	// declaring nothing, and dropping them made fifteen real units across the
	// fleet read as empty.
	"not_an_internet_socket",
	// unknown is a value that matched no documented form.
	"unknown",
}

// SocketUnitListen is one Listen* assignment, of any of the eight forms
// systemd.socket(5) defines. See SocketUnitListenDirectives.
//
// The honesty rule this type exists to hold: a bare port specifies no address.
// systemd.socket(5) says a single number "is read as port number to listen on
// via IPv6", and that depending on BindIPv6Only= "this might result in the
// service being available via both IPv6 and IPv4 (default) or just via IPv6",
// where the default follows /proc/sys/net/ipv6/bindv6only. So the file alone
// does not decide the address or the family, and this type never fills either
// one in for a bare port. Address and AddressFamily stay empty and
// AddressSpecified stays false, and the marshaller rejects any entry that
// claims otherwise.
type SocketUnitListen struct {
	// Directive is "ListenStream" or "ListenDatagram". For IP sockets the
	// first is TCP and the second UDP (systemd.socket(5)).
	Directive string `json:"directive"`
	// Value is the assignment verbatim, sanitized. It is the quotable
	// evidence, and everything below is this collector's reading of it.
	Value string `json:"value"`
	// Kind is one of SocketUnitKinds.
	Kind string `json:"kind"`
	// AddressSpecified is whether the value carried an address. It is not
	// omitempty, because a measured false is the whole point for a bare port.
	AddressSpecified bool `json:"address_specified"`
	// Address is the address literal the value carried, empty when it
	// carried none.
	Address string `json:"address,omitempty"`
	// AddressFamily is "v4" or "v6" when the value carried an address of
	// that family, empty otherwise. It is the family of the literal in the
	// file and nothing more: an IPv6 literal can still answer IPv4 traffic
	// depending on BindIPv6Only= (systemd.socket(5)), so a reader must not
	// read this as "this family only".
	AddressFamily string `json:"address_family,omitempty"`
	// Port is the TCP or UDP port when the value carried one, 0 otherwise.
	// A vsock port is not one of these and is left at 0.
	Port int `json:"port,omitempty"`
}

// InterfaceAddressesSection lists the addresses the kernel says are assigned
// to this host's interfaces. It answers a different question from the sockets
// section: a socket bound to 0.0.0.0 says nothing about which addresses the
// host holds, and on most servers every service binds the wildcard, so the
// socket list alone leaves "which addresses is this machine" unanswered.
//
// It has no per-source map. The whole payload comes from one read, so a
// section-level verdict carries everything a reader needs, the same shape
// RuleFilesSection has. And the verdict is strict in the same way that one is
// (RECORD.md 4.46): one interface whose addresses could not be read makes the
// whole section say so, because a short list that reads as complete is the
// false all-quiet this product must never give.
//
// A partial list is still carried beside a failure status. The addresses that
// were read are real, and dropping them would lose evidence to make the
// output tidy.
type InterfaceAddressesSection struct {
	Section
	// Addresses is never omitted when the section is present: collected and
	// empty is a measured answer and has to be distinguishable from absent.
	Addresses []InterfaceAddress `json:"addresses"`
}

// InterfaceAddress is one address the host holds, on one interface.
//
// What is deliberately not here, so a later change does not add it back
// without a reason: the prefix length, because the question this section
// exists for is about an address and not about a network, and the document
// grows a field when something needs it rather than in case. And the kernel's
// address scope, because the stdlib read does not expose it and reading
// netlink by hand to get it would be more code in the agent for a value
// nothing yet consumes.
type InterfaceAddress struct {
	// Interface is the interface name as the kernel gave it, sanitized: an
	// interface name is host-chosen text like a process name (RECORD.md 4.14).
	Interface string `json:"interface"`
	// Family is "v4" or "v6", derived from the address itself and always
	// agreeing with it. v4 and v6 never get inferred from each other
	// (PRODUCT.md 4b).
	Family string `json:"family"`
	// Address is the literal address, with no prefix length and no zone
	// index.
	Address string `json:"address"`
	// Global is the agent's own reading of whether this address is a
	// globally routable unicast address. It is information for a person
	// reading the document at a terminal and **nothing is allowed to decide
	// anything from it**: the control plane re-derives probeability from the
	// address text itself (controlplane/app/authz.py, normalise_target), so a
	// host that flips this bit changes no decision anywhere. It is not
	// omitempty, because a measured false must appear rather than vanish.
	Global bool `json:"global"`
}

// NftablesSection is the kernel's nftables ruleset as read over netlink.
// Evidence only: tables, chains and rules as the kernel holds them, no
// interpretation of what they permit. Rule order inside a chain is semantic
// and is preserved exactly as the kernel returned it, never sorted.
type NftablesSection struct {
	Section
	Tables []NftTable `json:"tables,omitempty"`
}

// NftTable is one nftables table. Family and name identify it.
type NftTable struct {
	// Family is one of the values in NftFamilies, or "unknown" for a family
	// this build does not know. Never free text.
	Family string `json:"family"`
	// Name is the table's own name, control-character sanitized.
	Name   string     `json:"name"`
	Chains []NftChain `json:"chains,omitempty"`
}

// NftChain is one chain. Base chains carry hook, priority and policy, and
// those decide whether traffic is filtered at all. A regular chain leaves
// them empty, it only sees what jumps to it.
type NftChain struct {
	Name string `json:"name"`
	// Type is the kernel's chain type string, for example "filter" or "nat",
	// read verbatim and sanitized.
	Type string `json:"type,omitempty"`
	// Hook is one of the values in NftHooks, or "unknown". Empty for a
	// regular chain.
	Hook string `json:"hook,omitempty"`
	// Priority orders base chains on the same hook. Nil for regular chains.
	Priority *int32 `json:"priority,omitempty"`
	// Policy is "accept" or "drop", the chain's fate for unmatched traffic.
	// Empty for regular chains.
	Policy string    `json:"policy,omitempty"`
	Rules  []NftRule `json:"rules,omitempty"`
}

// NftRule is one rule. Text is this agent's own rendering of the rule's
// expressions into nft-like syntax, and Rendered says plainly how much of the
// rule the renderer understood, so a partially understood rule can never
// read as a fully quoted one (the accuracy rule).
type NftRule struct {
	Text string `json:"text"`
	// Rendered is "full" when every expression was rendered, "partial" when
	// at least one fell back to a bracketed placeholder, "none" when nothing
	// was understood.
	Rendered string `json:"rendered"`
	// Comment is the rule author's own comment when present, sanitized.
	Comment string `json:"comment,omitempty"`
}

// NftFamilies and NftHooks are the only values this agent emits for the
// corresponding fields, "unknown" included. The marshaller fails closed on
// anything else.
var (
	NftFamilies = []string{"ip", "ip6", "inet", "arp", "bridge", "netdev", "unknown"}
	NftHooks    = []string{"prerouting", "input", "forward", "output", "postrouting", "ingress", "unknown"}
)

// UfwSection is ufw's own configuration, read from its files, never by
// executing ufw. This is the naming layer: the nftables and iptables sections
// hold what the kernel enforces, this section holds what the admin asked ufw
// for, and the control plane compares the two. Runtime truth lives in the
// kernel sections; a difference between them and this file view is a finding,
// not an error.
type UfwSection struct {
	Section
	// Sources carries one verdict per file, keyed by UfwSources.
	Sources map[string]Section `json:"sources,omitempty"`
	// Conf is /etc/ufw/ufw.conf as key-value pairs, verbatim and sanitized.
	// ENABLED lives here.
	Conf map[string]string `json:"conf,omitempty"`
	// Defaults is /etc/default/ufw the same way. The default policies live
	// here, including DEFAULT_FORWARD_POLICY, which matters because ufw
	// filters forwarded traffic too (PRODUCT.md 4b).
	Defaults map[string]string `json:"defaults,omitempty"`
	// Rules and Rules6 are the "### tuple ###" lines ufw writes into
	// user.rules and user6.rules: the admin's rule list in ufw's own words,
	// verbatim and sanitized, in file order. v4 and v6 are separate files on
	// disk and stay separate here (PRODUCT.md 4b).
	Rules  []string `json:"rules,omitempty"`
	Rules6 []string `json:"rules6,omitempty"`
}

// UfwSources are the only keys allowed in UfwSection.Sources.
var UfwSources = []string{"ufw.conf", "default", "user.rules", "user6.rules"}

// FirewalldSection is firewalld's permanent configuration, read from its
// files. What firewalld actually materialised right now is in the nftables
// section (FirewallBackend permitting); this section is the intent it was
// configured with.
type FirewalldSection struct {
	Section
	// Sources carries one verdict per source, keyed by FirewalldSources.
	Sources map[string]Section `json:"sources,omitempty"`
	// Conf is /etc/firewalld/firewalld.conf as key-value pairs. DefaultZone,
	// FirewallBackend and StrictForwardPorts (PRODUCT.md 4d) live here.
	Conf map[string]string `json:"conf,omitempty"`
	// Zones holds every zone file found, from both the vendor directory and
	// the admin directory. firewalld lets a file in /etc override the
	// same-named vendor file; both are reported and the origin says which is
	// which, because the override resolution is a conclusion and conclusions
	// belong to the control plane.
	Zones []FirewalldZone `json:"zones,omitempty"`
}

// FirewalldSources are the only keys allowed in FirewalldSection.Sources.
var FirewalldSources = []string{"firewalld.conf", "etc_zones", "vendor_zones"}

// FirewalldZone is one zone file. Name is the file name without .xml, which
// is how firewalld names zones. Parsed is false when the file existed but was
// not valid XML, in which case only File, Origin and Name are meaningful.
type FirewalldZone struct {
	File string `json:"file"`
	// Origin is "etc" for /etc/firewalld/zones or "vendor" for
	// /usr/lib/firewalld/zones. Never any other value.
	Origin string `json:"origin"`
	Name   string `json:"name"`
	Parsed bool   `json:"parsed"`
	// Target is the zone's target attribute, verbatim: ACCEPT, DROP,
	// %%REJECT%%, or empty for the default.
	Target       string             `json:"target,omitempty"`
	Services     []string           `json:"services,omitempty"`
	Ports        []FirewalldPort    `json:"ports,omitempty"`
	Interfaces   []string           `json:"interfaces,omitempty"`
	SourceAddrs  []string           `json:"source_addrs,omitempty"`
	Masquerade   bool               `json:"masquerade,omitempty"`
	Forward      bool               `json:"forward,omitempty"`
	ForwardPorts []FirewalldForward `json:"forward_ports,omitempty"`
}

// FirewalldPort is one opened port or range, kept as text because the port
// attribute can be a range like "1024-2048".
type FirewalldPort struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

// FirewalldForward is one forward-port entry, all fields verbatim.
type FirewalldForward struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	ToPort   string `json:"to_port,omitempty"`
	ToAddr   string `json:"to_addr,omitempty"`
}
