// Package safety states the agent's security boundary as code, so the
// project's eight invariants are not only prose but something a test can
// assert and a reviewer can point at. The owner named agent security the number one
// priority; this package exists to make that priority checkable.
//
// It holds no logic that runs in production. It is a manifest plus the helpers
// that let the test suite prove the manifest is honoured. The value is that a
// future change which, say, adds an exec call or a listening socket has to also
// come here and delete the invariant that forbids it, which is a visible,
// reviewable act rather than a silent drift.
package safety

// Invariant is one security rule the agent must never break.
type Invariant struct {
	// ID is the invariant's number, SI-1 to SI-8.
	ID string
	// Rule is the one-line statement of the boundary.
	Rule string
}

// Invariants is the full set, as the project's working agreement states it.
// If this list and that document ever disagree, that is a bug in one of
// them, and the test
// TestInvariantsCoverAllSI guards the count.
var Invariants = []Invariant{
	{"SI-1", "outbound only: the agent has no listening socket, ever"},
	{"SI-2", "no remote exec: the agent acts on nothing in any response it receives"},
	{"SI-3", "read only: the agent cannot edit a firewall rule, there is no write path"},
	{"SI-4", "argv arrays only, and in this agent, no exec of host binaries at all"},
	{"SI-5", "none of their credentials: no provider tokens held, no SSH keys, ever"},
	{"SI-6", "authorised targets only: the agent probes nothing, it only reads its own host"},
	{"SI-7", "no version detection: the agent reads state, it never fingerprints a service"},
	{"SI-8", "typed telemetry: error classes only, no free-text error fields on the wire"},
}

// ForbiddenImports are import paths this agent must never depend on. os/exec
// would give it the ability to run another program, which the no-exec read
// mechanism (PRODUCT.md 4e) forbids. plugin would let it load code that was
// not in the binary the operator inspected, which is the same problem wearing
// a different hat. A source scan in the test suite
// enforces both.
var ForbiddenImports = []string{
	"os/exec",
	"plugin",
}

// ForbiddenListenSymbols are calls that would open a listening socket,
// forbidden by SI-1. The agent makes outbound requests only.
//
// The list is longer than the obvious three because the obvious three are not
// the only way to reach listen(2). net.ListenConfig is a struct whose method
// does the same job, net.FileListener turns an inherited descriptor into a
// listener without any of them, and syscall.Listen and unix.Listen are the
// raw call this agent is already close enough to the kernel to make. Each one
// is named so the scan flags it rather than reasoning about it.
var ForbiddenListenSymbols = []string{
	"net.Listen",
	"net.ListenTCP",
	"net.ListenUDP",
	"net.ListenIP",
	"net.ListenUnix",
	"net.ListenUnixgram",
	"net.ListenPacket",
	"net.ListenMulticastUDP",
	"net.ListenConfig",
	"net.FileListener",
	"net.FilePacketConn",
	// An inherited descriptor turned into a connection rather than a
	// listener. Socket activation hands the agent an accepted fd on 3, so
	// this reaches an inbound connection with nothing above it called.
	"net.FileConn",
	// The type, not only the package-level helpers above. `srv :=
	// http.Server{...}` then `srv.ListenAndServe()` is a method call on a
	// value, which the scan does not resolve, so the constructor is what
	// there is to name.
	"http.Server",
	// listen(2) is only needed for a stream socket. A bound datagram socket
	// receives without it, and this agent already imports `unix`.
	"unix.Bind",
	"syscall.Bind",
	// And the other end of a stream, in case a listen ever slips past.
	"unix.Accept",
	"unix.Accept4",
	"syscall.Accept",
	"syscall.Accept4",
	"http.ListenAndServe",
	"http.ListenAndServeTLS",
	"http.Serve",
	"http.ServeTLS",
	"tls.Listen",
	"tls.NewListener",
	"syscall.Listen",
	"unix.Listen",
}

// ForbiddenExecSymbols are calls that would start another program, forbidden
// by SI-4 and by the no-exec read decision. os.StartProcess is the one worth
// pointing at: it needs no os/exec import, so the import scan alone never
// sees it.
var ForbiddenExecSymbols = []string{
	"exec.Command",
	"exec.CommandContext",
	"exec.LookPath",
	"os.StartProcess",
	"syscall.Exec",
	"syscall.ForkExec",
	"syscall.StartProcess",
	"unix.Exec",
	"unix.ForkExec",
	"plugin.Open",
}

// ResponseParsingBannedIn is the package that speaks to the control plane, and
// the packages it may not import. SI-2 says the agent acts on nothing in a
// response, and PRODUCT.md 4f makes the stronger claim that there is no
// response-parsing code at all. That claim is worth more than a promise, so
// the scan enforces it: a decoder imported into the report package is how the
// claim would quietly stop being true.
//
// The report client drains the body into io.Discard through a LimitReader and
// reads the status code. Nothing in that needs a decoder.
var (
	ResponseParsingBannedIn = "internal/report"

	ForbiddenDecoderImports = []string{
		"encoding/json",
		"encoding/xml",
		"encoding/gob",
		"encoding/asn1",
		"encoding/csv",
	}

	// ForbiddenBodyReadSymbols would pull a whole response body into memory
	// as a value the code could then act on. The drain is deliberately
	// io.Copy into io.Discard, which keeps nothing.
	ForbiddenBodyReadSymbols = []string{
		"io.ReadAll",
		"ioutil.ReadAll",
	}
)

// HTTPCapableFiles are the only production files allowed to import net/http.
// Network capability is a boundary like exec: it stays where it was declared,
// reviewed and tested, and a new file importing net/http fails the suite
// until it is deliberately added here, which is a visible, reviewable act.
var HTTPCapableFiles = []string{
	// One GET over each container runtime's local unix socket (PRODUCT.md 4e).
	"internal/collect/containers.go",
	// The outbound report channel, the agent's only network path off the host
	// (PRODUCT.md 4f).
	"internal/report/client.go",
}

// ForbiddenDialSymbols are package-level dial helpers banned everywhere, even
// in the HTTP-capable files. The two declared network paths build their
// clients explicitly (a unix-socket dialer, a TLS-floored transport that
// never follows redirects); a bare dial or a package-level http.Get would
// bypass exactly those restrictions, so their absence is enforced rather
// than assumed.
var ForbiddenDialSymbols = []string{
	"net.Dial",
	"net.DialTimeout",
	"net.DialTCP",
	"net.DialUDP",
	"net.DialIP",
	"net.DialUnix",
	"tls.Dial",
	"http.Get",
	"http.Post",
	"http.PostForm",
	"http.Head",
}

// ForbiddenNftWriteSymbols are the methods on nftables.Conn that mutate the
// kernel's ruleset or queue a mutation for Flush to commit. SI-3 says the
// agent is read only: it cannot edit a firewall rule, and there is no write
// path in v1. The nftables collector holds a live netlink connection whose
// write methods are exactly as reachable as its read methods, and systemd's
// ProtectSystem=strict does not stand in the way because the ruleset is
// written over netlink, which CAP_NET_ADMIN grants. This list is what makes
// SI-3 checkable rather than a promise. The names were read from the
// library's exported API (github.com/google/nftables v0.3.0, go doc), never
// from memory.
//
// Unlike the manifests above, these are bare method names rather than
// package-qualified symbols, because every write in the library is a method
// on a Conn value and a method call carries no package qualifier. The scan
// therefore matches the name on any receiver, and the test file explains why
// that bluntness is safe here.
var ForbiddenNftWriteSymbols = []string{
	// Flush is the write. The Add, Del, Insert and Replace calls below queue
	// messages inside the process, and Flush is what sends the batch to the
	// kernel. The name sounds like housekeeping, which is exactly why it is
	// called out first.
	"Flush",
	// FlushRuleset erases every table on the host in one queued message.
	"FlushRuleset",
	"FlushTable",
	"FlushChain",
	"FlushSet",
	// Tables, chains and rules.
	"AddTable",
	"CreateTable",
	"DelTable",
	"AddChain",
	"DelChain",
	"AddRule",
	"InsertRule",
	"ReplaceRule",
	"DelRule",
	// Sets and their elements.
	"AddSet",
	"DelSet",
	"SetAddElements",
	"SetDeleteElements",
	// Named objects (counters, quotas) and flowtables.
	"AddObj",
	"AddObject",
	"DeleteObject",
	"AddFlowtable",
	"DelFlowtable",
	// The reset family does its own netlink round trip at call time and
	// zeroes the counter or quota in the kernel as it reads it. A read with a
	// side effect is still a write.
	"GetObjReset",
	"ResetObject",
	"ResetObjects",
	"ResetNamedObjects",
}
