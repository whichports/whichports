package collect

// The OS matrix (board card "M1 agent: OS-matrix test fixtures including
// hostile inputs"). Each profile under testdata/procfs/<name>/net is a
// /proc/net snapshot the collector must read correctly, checked against
// hand-written expectations. The expectations were additionally cross-checked
// against an independent decoder, not against this package's own output, so a
// shared decoding bug cannot hide.
//
// Where the fixtures come from:
//
//	ubuntu-2604   Captured 2026-08-12 from Ubuntu 26.04 LTS, kernel
//	              7.0.0-29-generic, amd64, read as an unprivileged user, which
//	              is why the pointer column is zeroed. Real addresses were
//	              rewritten to documentation ranges (RFC 5737, RFC 3849)
//	              before committing. Header, column layout, field widths,
//	              socket states, uids, inodes and the repeated udp hash-bucket
//	              sl values are as captured. Carries a dual-stack detail worth
//	              keeping: the web server listens on [::] only, so its v4
//	              reachability exists with no v4 socket row at all.
//	almalinux-10  Captured 2026-08-12 from AlmaLinux 10.2, kernel
//	              6.12.0-211.7.3.el10_2.x86_64, read as root, which is why the
//	              pointer column carries kernel addresses (rewritten to fixed
//	              fake ones, same width). Addresses and the box's service
//	              ports were rewritten the same way, layout untouched. Carries
//	              the v6 shapes worth testing: a ULA listener, a link-local
//	              socket with an EUI-64 interface id, and a wildcard high
//	              port.
//	el7-3.10      Constructed, not captured. Rows follow the v3.10 kernel's
//	              own output formats, read from net/ipv4/tcp_ipv4.c
//	              (get_tcp4_sock) and net/ipv4/udp.c (udp4_format_sock) at the
//	              v3.10 tag on 2026-08-12. That is the kernel line el7
//	              machines run. There are no tcp6/udp6 files: on a host whose
//	              kernel has no v6 files the empty v6 answer is measured, not
//	              guessed, because the collector looked and the source was not
//	              there.
//	hostile-malformed  Constructed. Two valid rows surrounded by every broken
//	              shape we could produce: a truncated row, free text, a port
//	              past 65535, a wrong-length address, an unparseable state, a
//	              stray second header, a negative port. Also a port-0 row,
//	              which a kernel never emits because binding port 0 assigns a
//	              real ephemeral port, and which is reported verbatim because
//	              the document reports evidence, and a v4-mapped v6 listener,
//	              the shape that exposed the bare-v4 rendering bug fixed in
//	              decodeV6.
//	hostile-binary     Constructed. Not a socket table at all, with terminal
//	              escape bytes mixed in. Must come back as a parse failure,
//	              never as "collected, nothing listening", because a false
//	              all-quiet is the worst answer this product can give.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

func TestOSMatrix(t *testing.T) {
	// sock builds one expected socket. The uid is part of every expectation
	// because every captured row carries the column, and the values below were
	// read from the fixture files by hand, not from this package's output.
	sock := func(proto, fam, addr string, port int, uid int64) hostdoc.ListeningSocket {
		u := uid
		return hostdoc.ListeningSocket{Protocol: proto, Family: fam,
			BindAddress: addr, Port: port, OwnerUID: &u}
	}
	// Shorthands for the per-source verdicts every profile must now carry.
	// The matrix roots hold no etc/passwd, so a collected section reports the
	// owner-name lookup as not_present rather than staying silent about it.
	collected := hostdoc.Section{Status: hostdoc.StatusCollected}
	notPresent := hostdoc.Section{Status: hostdoc.StatusNotPresent}
	parseFailed := hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	allCollected := map[string]hostdoc.Section{
		"tcp": collected, "tcp6": collected, "udp": collected, "udp6": collected,
		"passwd": notPresent,
	}
	cases := []struct {
		profile     string
		wantStatus  hostdoc.SectionStatus
		wantCause   hostdoc.ErrorCause
		wantSources map[string]hostdoc.Section
		want        []hostdoc.ListeningSocket
	}{
		{
			profile:     "ubuntu-2604",
			wantStatus:  hostdoc.StatusCollected,
			wantSources: allCollected,
			want: []hostdoc.ListeningSocket{
				sock("tcp", "v4", "0.0.0.0", 22, 0),
				sock("tcp", "v4", "127.0.0.53", 53, 990),
				sock("tcp", "v4", "127.0.0.54", 53, 990),
				sock("tcp", "v4", "127.0.0.1", 2019, 999),
				sock("tcp", "v6", "::", 22, 0),
				sock("tcp", "v6", "::", 80, 999),
				sock("tcp", "v6", "::", 443, 999),
				sock("udp", "v4", "127.0.0.53", 53, 990),
				sock("udp", "v4", "127.0.0.54", 53, 990),
				sock("udp", "v4", "192.0.2.10", 68, 998),
				sock("udp", "v4", "127.0.0.1", 323, 0),
				sock("udp", "v6", "::1", 323, 0),
				sock("udp", "v6", "::", 443, 999),
			},
		},
		{
			profile:     "almalinux-10",
			wantStatus:  hostdoc.StatusCollected,
			wantSources: allCollected,
			want: []hostdoc.ListeningSocket{
				sock("tcp", "v4", "0.0.0.0", 22, 0),
				sock("tcp", "v4", "198.51.100.23", 443, 0),
				sock("tcp", "v4", "0.0.0.0", 3000, 0),
				sock("tcp", "v4", "0.0.0.0", 8080, 0),
				sock("tcp", "v4", "0.0.0.0", 8443, 0),
				sock("tcp", "v4", "198.51.100.23", 40223, 0),
				sock("tcp", "v6", "::", 22, 0),
				sock("tcp", "v6", "2001:db8::aaaa:bbbb", 443, 0),
				sock("tcp", "v6", "::", 3000, 0),
				sock("tcp", "v6", "::", 8443, 0),
				sock("tcp", "v6", "::", 9090, 0),
				sock("tcp", "v6", "2001:db8::aaaa:bbbb", 61764, 0),
				sock("udp", "v4", "127.0.0.1", 323, 0),
				sock("udp", "v4", "0.0.0.0", 40000, 0),
				sock("udp", "v6", "::1", 323, 0),
				sock("udp", "v6", "fe80::203:4ff:fe05:607", 546, 0),
				sock("udp", "v6", "::", 40000, 0),
			},
		},
		{
			profile:    "el7-3.10",
			wantStatus: hostdoc.StatusCollected,
			wantSources: map[string]hostdoc.Section{
				"tcp": collected, "tcp6": notPresent, "udp": collected, "udp6": notPresent,
				"passwd": notPresent,
			},
			want: []hostdoc.ListeningSocket{
				sock("tcp", "v4", "0.0.0.0", 22, 0),
				sock("tcp", "v4", "127.0.0.1", 25, 0),
				sock("udp", "v4", "0.0.0.0", 123, 0),
			},
		},
		{
			profile:    "hostile-malformed",
			wantStatus: hostdoc.StatusCollected,
			wantSources: map[string]hostdoc.Section{
				"tcp": collected, "tcp6": collected, "udp": notPresent, "udp6": notPresent,
				"passwd": notPresent,
			},
			want: []hostdoc.ListeningSocket{
				sock("tcp", "v4", "127.0.0.1", 0, 0),
				sock("tcp", "v4", "0.0.0.0", 22, 0),
				sock("tcp", "v6", "::ffff:192.0.2.10", 80, 0),
			},
		},
		{
			profile:    "hostile-binary",
			wantStatus: hostdoc.StatusReadError,
			wantCause:  hostdoc.CauseParseFailed,
			wantSources: map[string]hostdoc.Section{
				"tcp": parseFailed, "tcp6": notPresent, "udp": notPresent, "udp6": notPresent,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.profile, func(t *testing.T) {
			root := filepath.Join("testdata", "procfs", c.profile)
			sec := CollectSockets(root, root, nil)

			if sec.Status != c.wantStatus || sec.Cause != c.wantCause {
				t.Fatalf("status=%q cause=%q, want %q/%q", sec.Status, sec.Cause, c.wantStatus, c.wantCause)
			}
			if len(sec.Sources) != len(c.wantSources) {
				t.Fatalf("sources = %v, want %v", sec.Sources, c.wantSources)
			}
			for key, want := range c.wantSources {
				if got := sec.Sources[key]; got != want {
					t.Errorf("sources[%q] = %+v, want %+v", key, got, want)
				}
			}
			if len(sec.Listening) != len(c.want) {
				for _, s := range sec.Listening {
					t.Logf("got %s/%s %s:%d", s.Protocol, s.Family, s.BindAddress, s.Port)
				}
				t.Fatalf("listening count = %d, want %d", len(sec.Listening), len(c.want))
			}
			for i, w := range c.want {
				g := sec.Listening[i]
				if g.Protocol != w.Protocol || g.Family != w.Family ||
					g.BindAddress != w.BindAddress || g.Port != w.Port {
					t.Errorf("[%d] got %s/%s %s:%d, want %s/%s %s:%d", i,
						g.Protocol, g.Family, g.BindAddress, g.Port,
						w.Protocol, w.Family, w.BindAddress, w.Port)
				}
				if !sameUID(g.OwnerUID, w.OwnerUID) {
					t.Errorf("[%d] owner uid = %s, want %s", i,
						uidString(g.OwnerUID), uidString(w.OwnerUID))
				}
				// The matrix roots hold no pid directories and no passwd
				// file, so nothing may claim a process or a user name.
				if g.PID != 0 || g.ProcessName != "" || g.OwnerName != "" {
					t.Errorf("[%d] unexpected attribution: %+v", i, g)
				}
			}

			// Whatever a profile produced must survive the document's own
			// fail-closed marshaller and must be clean on a terminal.
			d := hostdoc.New("h", 1)
			d.Sockets = sec
			b, err := hostdoc.Marshal(d)
			if err != nil {
				t.Fatalf("profile output failed the document contract: %v", err)
			}
			assertTerminalSafe(t, b)
		})
	}
}

// sameUID compares two optional uids: equal when both absent or both carry
// the same value.
func sameUID(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// uidString prints an optional uid for a failure message.
func uidString(u *int64) string {
	if u == nil {
		return "absent"
	}
	return itoa(int(*u))
}

// assertTerminalSafe fails if the marshalled document contains anything a
// terminal could interpret as a control sequence: C0 controls other than the
// newlines of indented JSON, DEL, the C1 range, or bytes that are not valid
// UTF-8. stdout mode prints this byte stream on an operator's terminal, so
// this property is part of the contract, whatever hostile names the host held.
func assertTerminalSafe(t *testing.T, b []byte) {
	t.Helper()
	for i := 0; i < len(b); {
		r, sz := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && sz == 1 {
			t.Fatalf("invalid UTF-8 byte 0x%02x at offset %d", b[i], i)
		}
		if r != '\n' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)) {
			t.Fatalf("control character U+%04X at offset %d", r, i)
		}
		i += sz
	}
}

// TestHostileCommSanitized wires a process whose self-chosen name carries an
// ANSI colour escape, a bell, a newline and a UTF-8 encoded C1 control. The
// name a process gives itself is untrusted input. Every control character
// must come out as '?', and the marshalled document must stay terminal-safe.
func TestHostileCommSanitized(t *testing.T) {
	root := t.TempDir()
	netDir := filepath.Join(root, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tcp := "  sl  local_address rem_address   st ... inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 0 0 0 0 0 777 1 0\n"
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	pidDir := filepath.Join(root, "51")
	fdDir := filepath.Join(pidDir, "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hostileComm := "e\x1b[31mvil\x07\nx\xc2\x9b\n"
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte(hostileComm), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[777]", filepath.Join(fdDir, "3")); err != nil {
		t.Fatal(err)
	}

	sec := CollectSockets(root, root, nil)
	if len(sec.Listening) != 1 {
		t.Fatalf("want 1 socket, got %d", len(sec.Listening))
	}
	if got, want := sec.Listening[0].ProcessName, "e?[31mvil??x?"; got != want {
		t.Fatalf("sanitized comm = %q, want %q", got, want)
	}

	d := hostdoc.New("h", 1)
	d.Sockets = sec
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, b)
	if bytes.ContainsAny(b, "\x1b\x07") {
		t.Fatal("raw escape bytes made it into the document")
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"sshd":          "sshd",
		"a\x7fb":        "a?b",
		"tab\tname":     "tab?name",
		"c1\u009bcsi":   "c1?csi",
		"\xffz":         "�z", // invalid byte becomes the replacement rune
		"nginx: worker": "nginx: worker",
		"café":          "café", // ordinary non-ASCII text passes through
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestReuseportDeterministicOrder pins the pid tie-break: with SO_REUSEPORT
// several processes hold sockets on an identical address and port, and two
// runs over the same state must still produce byte-identical documents.
func TestReuseportDeterministicOrder(t *testing.T) {
	root := t.TempDir()
	netDir := filepath.Join(root, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tcp := "  sl  local_address rem_address   st ... inode\n" +
		"   0: 00000000:0050 00000000:0000 0A 0 0 0 0 0 7001 1 0\n" +
		"   1: 00000000:0050 00000000:0000 0A 0 0 0 0 0 7002 1 0\n"
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	addProc := func(pid, comm, inode string) {
		fdDir := filepath.Join(root, pid, "fd")
		if err := os.MkdirAll(fdDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("socket:["+inode+"]", filepath.Join(fdDir, "3")); err != nil {
			t.Fatal(err)
		}
	}
	// The higher pid owns the row that appears first in the file, so input
	// order and pid order disagree on purpose.
	addProc("200", "alpha", "7001")
	addProc("100", "beta", "7002")

	sec := CollectSockets(root, root, nil)
	if len(sec.Listening) != 2 {
		t.Fatalf("want 2 reuseport sockets, got %d", len(sec.Listening))
	}
	if sec.Listening[0].PID != 100 || sec.Listening[1].PID != 200 {
		t.Fatalf("pid order = %d,%d, want 100,200", sec.Listening[0].PID, sec.Listening[1].PID)
	}

	d1 := hostdoc.New("h", 1)
	d1.Sockets = sec
	d2 := hostdoc.New("h", 1)
	d2.Sockets = CollectSockets(root, root, nil)
	b1, err1 := hostdoc.Marshal(d1)
	b2, err2 := hostdoc.Marshal(d2)
	if err1 != nil || err2 != nil {
		t.Fatalf("marshal errors: %v %v", err1, err2)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("two collections of the same reuseport state differ")
	}
}

// TestOversizedLineIsReadError feeds a single line past the scanner's 1 MiB
// limit. The scanner reports an error, and the section must say read_error
// rather than pretend the file was empty.
func TestOversizedLineIsReadError(t *testing.T) {
	content := "  sl  local_address rem_address   st\n" + strings.Repeat("A", 2*1024*1024) + "\n"
	root := writeProcNet(t, content, noFile, noFile, noFile)
	sec := CollectSockets(root, root, nil)
	if sec.Status != hostdoc.StatusReadError || sec.Cause != hostdoc.CauseParseFailed {
		t.Fatalf("status=%q cause=%q, want read_error/parse_failed", sec.Status, sec.Cause)
	}
}

// TestLargeFileParsesCompletely builds a hundred thousand rows, alternating
// listener and established, and requires every listener to survive. Silent
// truncation on a busy host would be an invisible lie.
func TestLargeFileParsesCompletely(t *testing.T) {
	var b strings.Builder
	b.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	const rows = 100_000
	for i := 0; i < rows; i++ {
		st := "0A"
		if i%2 == 1 {
			st = "01"
		}
		fmt.Fprintf(&b, "%4d: 0100007F:%04X 00000000:0000 %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n",
			i, i%65535+1, st, 100000+i)
	}
	root := writeProcNet(t, b.String(), noFile, noFile, noFile)
	sec := CollectSockets(root, root, nil)
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	if len(sec.Listening) != rows/2 {
		t.Fatalf("listener count = %d, want %d", len(sec.Listening), rows/2)
	}
}

func TestHeaderOnlyAndWhitespaceFiles(t *testing.T) {
	// A header with no rows, and a file of blank lines. Both parse to zero
	// listeners: no data lines means nothing was there, which is a collected
	// empty answer, not a parse failure.
	headerOnly := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	root := writeProcNet(t, headerOnly, noFile, noFile, noFile)
	if sec := CollectSockets(root, root, nil); sec.Status != hostdoc.StatusCollected || len(sec.Listening) != 0 {
		t.Fatalf("header-only: status=%q count=%d", sec.Status, len(sec.Listening))
	}
	root2 := writeProcNet(t, "\n   \n\t\n", noFile, noFile, noFile)
	if sec := CollectSockets(root2, root2, nil); sec.Status != hostdoc.StatusCollected || len(sec.Listening) != 0 {
		t.Fatalf("whitespace-only: status=%q count=%d", sec.Status, len(sec.Listening))
	}
}

// TestGarbageBesideGoodFileStaysCollected pins the aggregation rule: if one
// source parses and another is garbage, the section is collected and carries
// what parsed, and the sources map names the source that failed. This is the
// case the per-source status exists for (RECORD.md 4.15): a broken tcp6 next
// to a healthy tcp must never read as "v6 measured and empty".
func TestGarbageBesideGoodFileStaysCollected(t *testing.T) {
	good := "  sl  local_address rem_address   st ... inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 0 0 0 0 0 12345 1 0\n"
	root := writeProcNet(t, good, "complete nonsense\nmore nonsense\n", noFile, noFile)
	sec := CollectSockets(root, root, nil)
	if sec.Status != hostdoc.StatusCollected || len(sec.Listening) != 1 {
		t.Fatalf("status=%q count=%d, want collected with 1", sec.Status, len(sec.Listening))
	}
	if got := sec.Sources["tcp"]; got.Status != hostdoc.StatusCollected {
		t.Fatalf("sources[tcp] = %+v, want collected", got)
	}
	if got := sec.Sources["tcp6"]; got.Status != hostdoc.StatusReadError || got.Cause != hostdoc.CauseParseFailed {
		t.Fatalf("sources[tcp6] = %+v, want read_error/parse_failed", got)
	}
	if got := sec.Sources["udp"]; got.Status != hostdoc.StatusNotPresent {
		t.Fatalf("sources[udp] = %+v, want not_present", got)
	}
}

func TestV4MappedDecodesExplicitly(t *testing.T) {
	// The kernel stores ::ffff:192.0.2.10 for an AF_INET6 socket bound to a
	// mapped address. net.IP.String() alone would render it "192.0.2.10" and
	// make a v6 socket wear a v4 address, so decodeV6 keeps the mapped form.
	got, ok := decodeV6("0000000000000000FFFF00000A0200C0")
	if !ok || got != "::ffff:192.0.2.10" {
		t.Fatalf("mapped decode = %q ok=%v, want ::ffff:192.0.2.10 true", got, ok)
	}
}
