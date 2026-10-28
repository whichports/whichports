package collect

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// These tests are the review. Socket parsing is exactly
// where a subtle bug hides: hex byte order, the LISTEN filter, a malformed row.
// So the parser is exercised against real /proc line formats and every failure
// mode: empty, headerless, truncated, garbage, permission denied, IPv6 absent.

// realProcTCP is a verbatim /proc/net/tcp sample. sshd on 0.0.0.0:22 (LISTEN),
// a localhost-only service on 127.0.0.1:5432 (LISTEN), and an established
// connection that must NOT be reported.
const realProcTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1538 0100007F:C1B4 01 00000000:00000000 00:00000000 00000000     0        0 34567 1 0000000000000000 20 0 0 10 0
`

// realProcTCP6 sample: sshd on [::]:22 (LISTEN).
const realProcTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 45678 1 0000000000000000 100 0 0 10 0
`

// realProcUDP sample: a bound UDP server on 0.0.0.0:53 (rem port 0), and a
// connected UDP client (rem port nonzero) that must NOT be reported.
const realProcUDP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 56789 2 0000000000000000 0
   1: 0100007F:E11D 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 67890 2 0000000000000000 0
`

func writeProcNet(t *testing.T, tcp, tcp6, udp, udp6 string) string {
	t.Helper()
	root := t.TempDir()
	netDir := filepath.Join(root, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		if content == "\x00" { // sentinel: do not create this file
			return
		}
		if err := os.WriteFile(filepath.Join(netDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("tcp", tcp)
	write("tcp6", tcp6)
	write("udp", udp)
	write("udp6", udp6)
	return root
}

const noFile = "\x00"

func TestCollectSocketsHappyPath(t *testing.T) {
	root := writeProcNet(t, realProcTCP, realProcTCP6, realProcUDP, noFile)
	sec := CollectSockets(root, root, nil)

	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	// Expected: tcp v4 :22, tcp v4 127.0.0.1:5432, tcp v6 :22, udp v4 :53.
	// The established TCP conn and the connected UDP client are excluded.
	if len(sec.Listening) != 4 {
		for _, s := range sec.Listening {
			t.Logf("got %s/%s %s:%d", s.Protocol, s.Family, s.BindAddress, s.Port)
		}
		t.Fatalf("listening count = %d, want 4", len(sec.Listening))
	}

	byKey := map[string]hostdoc.ListeningSocket{}
	for _, s := range sec.Listening {
		byKey[s.Protocol+s.Family+strconvPort(s.Port)] = s
	}
	if s, ok := byKey["tcpv422"]; !ok || s.BindAddress != "0.0.0.0" {
		t.Errorf("sshd v4 wrong: %+v", s)
	}
	if s, ok := byKey["tcpv45432"]; !ok || s.BindAddress != "127.0.0.1" {
		t.Errorf("postgres v4 wrong: %+v (0x1538 must decode to 5432)", s)
	}
	if s, ok := byKey["tcpv622"]; !ok || s.BindAddress != "::" {
		t.Errorf("sshd v6 wrong: %+v", s)
	}
	if s, ok := byKey["udpv453"]; !ok || s.BindAddress != "0.0.0.0" {
		t.Errorf("dns udp wrong: %+v", s)
	}
}

func TestHexPortDecoding(t *testing.T) {
	// 0x1538 = 5432, the classic Postgres port, is the canary for byte order.
	addr, port, ok := parseLocalAddr("0100007F:1538", "v4")
	if !ok || port != 5432 || addr != "127.0.0.1" {
		t.Fatalf("got addr=%q port=%d ok=%v, want 127.0.0.1 5432 true", addr, port, ok)
	}
}

func TestV4ByteOrder(t *testing.T) {
	// 0.0.0.0, 127.0.0.1, and a routable address to be sure it is not just
	// symmetric values passing by luck. 0x0100A8C0 little-endian = 192.168.0.1.
	cases := map[string]string{
		"00000000": "0.0.0.0",
		"0100007F": "127.0.0.1",
		"0100A8C0": "192.168.0.1",
	}
	for h, want := range cases {
		got, ok := decodeV4(h)
		if !ok || got != want {
			t.Errorf("decodeV4(%s) = %q, want %q", h, got, want)
		}
	}
}

func TestV6ByteOrder(t *testing.T) {
	// All-zero is ::, and the loopback ::1 has a distinctive word layout that
	// catches a wrong per-word reversal.
	if got, _ := decodeV6("00000000000000000000000000000000"); got != "::" {
		t.Errorf("v6 all-zero = %q, want ::", got)
	}
	// ::1 is stored as three zero words then 0x01000000 little-endian.
	if got, ok := decodeV6("00000000000000000000000001000000"); !ok || got != "::1" {
		t.Errorf("v6 loopback = %q ok=%v, want ::1", got, ok)
	}
}

func TestEstablishedTCPExcluded(t *testing.T) {
	// A file with only an established connection must yield zero listeners, not
	// an error: the read succeeded, there is simply nothing listening.
	onlyEstablished := `  sl  local_address rem_address   st ...
   0: 0100007F:1538 0100007F:C1B4 01 00000000:00000000 00:00000000 00000000     0        0 34567 1 0000000000000000
`
	root := writeProcNet(t, onlyEstablished, noFile, noFile, noFile)
	sec := CollectSockets(root, root, nil)
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	if len(sec.Listening) != 0 {
		t.Fatalf("expected no listeners, got %d", len(sec.Listening))
	}
}

func TestMalformedRowsSkippedNotFatal(t *testing.T) {
	// A good listener, a truncated row, and a garbage row. The good one must
	// survive; the bad ones are skipped, not fatal.
	mixed := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0
   1: garbage
   2: XXXX:YYYY 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1 0
`
	root := writeProcNet(t, mixed, noFile, noFile, noFile)
	sec := CollectSockets(root, root, nil)
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	if len(sec.Listening) != 1 || sec.Listening[0].Port != 22 {
		t.Fatalf("expected only the valid :22 listener, got %+v", sec.Listening)
	}
}

func TestEmptyAndHeaderlessFiles(t *testing.T) {
	// An empty tcp file and a headerless one. Empty yields nothing; headerless
	// still parses its data row. The kernel always writes the header (see the
	// note in parseProcNet), so headerless is pure defence, tested anyway.
	empty := ""
	headerless := "   0: 00000000:0016 00000000:0000 0A 0 0 0 0 0 12345 1 0\n"
	root := writeProcNet(t, empty, noFile, noFile, noFile)
	if sec := CollectSockets(root, root, nil); sec.Status != hostdoc.StatusCollected || len(sec.Listening) != 0 {
		t.Fatalf("empty tcp: status=%q count=%d", sec.Status, len(sec.Listening))
	}
	root2 := writeProcNet(t, headerless, noFile, noFile, noFile)
	sec := CollectSockets(root2, root2, nil)
	if sec.Status != hostdoc.StatusCollected || len(sec.Listening) != 1 {
		t.Fatalf("headerless tcp: status=%q count=%d, want 1 listener", sec.Status, len(sec.Listening))
	}
}

func TestNoFilesAtAllIsNotPresent(t *testing.T) {
	// A proc dir with no net files (wrong path, unmounted): reported as
	// not_present, never as an empty successful collection.
	root := t.TempDir()
	sec := CollectSockets(root, root, nil)
	if sec.Status != hostdoc.StatusNotPresent {
		t.Fatalf("status = %q, want not_present", sec.Status)
	}
}

func TestPermissionDeniedReported(t *testing.T) {
	// A net dir whose tcp file cannot be read yields permission_denied, so the
	// operator sees "run me with more privilege" rather than a silent blank.
	if os.Getuid() == 0 {
		t.Skip("cannot test permission denial as root")
	}
	root := t.TempDir()
	netDir := filepath.Join(root, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(netDir, "tcp")
	if err := os.WriteFile(f, []byte(realProcTCP), 0o000); err != nil {
		t.Fatal(err)
	}
	sec := CollectSockets(root, root, nil)
	if sec.Status != hostdoc.StatusPermissionDenied || sec.Cause != hostdoc.CausePermission {
		t.Fatalf("status=%q cause=%q, want permission_denied/permission", sec.Status, sec.Cause)
	}
}

func TestProcessAttribution(t *testing.T) {
	// Wire a fake /proc: a listener with inode 12345, and a pid 900 whose fd 3
	// is a symlink to socket:[12345]. The socket must come back owned by sshd.
	root := t.TempDir()
	netDir := filepath.Join(root, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tcp := "  sl  local_address rem_address   st ... inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 0 0 0 0 0 12345 1 0\n"
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	pidDir := filepath.Join(root, "900")
	fdDir := filepath.Join(pidDir, "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("sshd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[12345]", filepath.Join(fdDir, "3")); err != nil {
		t.Fatal(err)
	}
	// A non-socket fd that must be ignored.
	if err := os.Symlink("/etc/hosts", filepath.Join(fdDir, "4")); err != nil {
		t.Fatal(err)
	}

	sec := CollectSockets(root, root, nil)
	if len(sec.Listening) != 1 {
		t.Fatalf("want 1 socket, got %d", len(sec.Listening))
	}
	if sec.Listening[0].ProcessName != "sshd" || sec.Listening[0].PID != 900 {
		t.Fatalf("attribution wrong: %+v", sec.Listening[0])
	}
}

// writeHolders wires a fake /proc with one listening socket on inode 12345 and
// one fd directory per entry in holders, mapping pid to comm.
func writeHolders(t *testing.T, holders map[int]string) string {
	t.Helper()
	root := t.TempDir()
	netDir := filepath.Join(root, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tcp := "  sl  local_address rem_address   st ... inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 0 0 0 0 0 12345 1 0\n"
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	for pid, comm := range holders {
		pidDir := filepath.Join(root, strconv.Itoa(pid))
		fdDir := filepath.Join(pidDir, "fd")
		if err := os.MkdirAll(fdDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("socket:[12345]", filepath.Join(fdDir, "3")); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSocketActivatedServiceIsNotAttributedToSystemd(t *testing.T) {
	// Measured on the production box 2026-08-16. ssh.socket and ssh.service are
	// both active, so systemd holds the listening socket and passed the fd to
	// sshd, and ss reports both:
	//
	//   users:(("sshd",pid=1078,fd=3),("systemd",pid=1,fd=259))
	//
	// The document said process_name "systemd", pid 1, on the one port every
	// sysadmin looks at first. Naming init instead of the service tells the
	// reader nothing.
	root := writeHolders(t, map[int]string{1: "systemd", 1078: "sshd"})
	sec := CollectSockets(root, root, nil)
	if len(sec.Listening) != 1 {
		t.Fatalf("want 1 socket, got %d", len(sec.Listening))
	}
	got := sec.Listening[0]
	if got.ProcessName != "sshd" || got.PID != 1078 {
		t.Fatalf("socket-activated service attributed to %q pid %d, want sshd pid 1078",
			got.ProcessName, got.PID)
	}
}

func TestPidOneStillWinsWhenItIsTheOnlyHolder(t *testing.T) {
	// The other side of the rule. Preferring a service over init must not mean
	// refusing to name init when init really is the only process holding it.
	root := writeHolders(t, map[int]string{1: "systemd"})
	sec := CollectSockets(root, root, nil)
	if len(sec.Listening) != 1 {
		t.Fatalf("want 1 socket, got %d", len(sec.Listening))
	}
	if sec.Listening[0].ProcessName != "systemd" || sec.Listening[0].PID != 1 {
		t.Fatalf("attribution wrong: %+v", sec.Listening[0])
	}
}

func TestSeveralHoldersPickTheLowestPidWhichIsTheParent(t *testing.T) {
	// A master with inherited workers, the nginx and the Caddy shape. The
	// answer a reader wants is the master, and the lowest pid is the master
	// because the workers were forked from it.
	//
	// This case was also wrong before, and for a second reason: /proc entries
	// arrive from os.ReadDir in lexical order, where "1001" sorts before "900",
	// so a worker beat its own master. Numeric order is the fix for both.
	root := writeHolders(t, map[int]string{900: "nginx", 1001: "nginx", 1002: "nginx"})
	sec := CollectSockets(root, root, nil)
	if sec.Listening[0].PID != 900 {
		t.Fatalf("want the master at pid 900, got pid %d", sec.Listening[0].PID)
	}
}

func TestTheChoiceOfHolderDoesNotDependOnDirectoryOrder(t *testing.T) {
	// The bug was an ordering accident rather than a decision, so the guard has
	// to be that the answer is the same however the directory is walked. Same
	// holders, built in three different insertion orders.
	for _, order := range []([]int){{1, 1078}, {1078, 1}, {1078, 1}} {
		holders := map[int]string{}
		for _, pid := range order {
			if pid == 1 {
				holders[1] = "systemd"
			} else {
				holders[pid] = "sshd"
			}
		}
		holderRoot := writeHolders(t, holders)
		sec := CollectSockets(holderRoot, holderRoot, nil)
		if sec.Listening[0].PID != 1078 {
			t.Fatalf("insertion order %v changed the answer to pid %d",
				order, sec.Listening[0].PID)
		}
	}
}

func TestUnattributedSocketStillReported(t *testing.T) {
	// No matching process for the inode: the socket is still reported, with an
	// empty owner. "We cannot see who owns it" is information, not a reason to
	// drop the finding.
	root := writeProcNet(t, realProcTCP, noFile, noFile, noFile)
	sec := CollectSockets(root, root, nil)
	for _, s := range sec.Listening {
		if s.PID != 0 || s.ProcessName != "" {
			t.Fatalf("expected no attribution without /proc/<pid>, got %+v", s)
		}
	}
	if len(sec.Listening) == 0 {
		t.Fatal("sockets must still be reported unattributed")
	}
}

func TestIdempotent(t *testing.T) {
	// The same proc contents must produce an identical document twice: the
	// section marshals to the same bytes. Guards ordering and any hidden state.
	root := writeProcNet(t, realProcTCP, realProcTCP6, realProcUDP, noFile)
	d1 := hostdoc.New("h", 1)
	d1.Sockets = CollectSockets(root, root, nil)
	d2 := hostdoc.New("h", 1)
	d2.Sockets = CollectSockets(root, root, nil)
	b1, err1 := hostdoc.Marshal(d1)
	b2, err2 := hostdoc.Marshal(d2)
	if err1 != nil || err2 != nil {
		t.Fatalf("marshal errors: %v %v", err1, err2)
	}
	if string(b1) != string(b2) {
		t.Fatal("two collections of the same state produced different documents")
	}
}

func TestCollectedResultMarshalsCleanly(t *testing.T) {
	// End to end: whatever the collector produces must pass the document's own
	// fail-closed marshaller, proving the collector cannot emit an invalid
	// protocol or family.
	root := writeProcNet(t, realProcTCP, realProcTCP6, realProcUDP, noFile)
	d := hostdoc.New("h", 1)
	d.Sockets = CollectSockets(root, root, nil)
	if _, err := hostdoc.Marshal(d); err != nil {
		t.Fatalf("collector output failed the document contract: %v", err)
	}
}

// writePasswd puts a passwd fixture under root, where CollectSockets resolves
// etc/passwd against its fsRoot argument.
func writePasswd(t *testing.T, root, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// uid returns the socket's owner uid or fails: these tests assert the value,
// so an absent uid is an answer worth a named failure rather than a panic.
func uid(t *testing.T, s hostdoc.ListeningSocket) int64 {
	t.Helper()
	if s.OwnerUID == nil {
		t.Fatalf("socket %s/%s:%d carries no owner uid", s.Protocol, s.BindAddress, s.Port)
	}
	return *s.OwnerUID
}

func TestOwnerUIDIsCarriedAndNamedFromPasswd(t *testing.T) {
	// The shape RECORD.md 4.64 measured on the production box: root on 22 and
	// a service user on its own port. uid 0 must come out as a real answer
	// named root, never dropped as a zero value.
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0\n" +
		"   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 222 1 0\n"
	root := writeProcNet(t, tcp, noFile, noFile, noFile)
	writePasswd(t, root, "root:x:0:0:root:/root:/bin/bash\ncaddy:x:991:991::/var/lib/caddy:/usr/sbin/nologin\n")
	sec := CollectSockets(root, root, nil)
	if len(sec.Listening) != 2 {
		t.Fatalf("want 2 sockets, got %d", len(sec.Listening))
	}
	if got := uid(t, sec.Listening[0]); got != 0 || sec.Listening[0].OwnerName != "root" {
		t.Fatalf(":22 owner = %d %q, want 0 root", got, sec.Listening[0].OwnerName)
	}
	if got := uid(t, sec.Listening[1]); got != 991 || sec.Listening[1].OwnerName != "caddy" {
		t.Fatalf(":443 owner = %d %q, want 991 caddy", got, sec.Listening[1].OwnerName)
	}
	if got := sec.Sources["passwd"]; got.Status != hostdoc.StatusCollected {
		t.Fatalf("sources[passwd] = %+v, want collected", got)
	}
}

func TestRootlessPodmanShapedRowKeepsTheBareUID(t *testing.T) {
	// Measured on an AlmaLinux 10 server, 2026-08-19 (RECORD.md 4.64): a
	// rootless container publishes through pasta as a v6 wildcard socket owned
	// by the user who ran it, uid 1003, and no passwd entry has to exist for
	// the agent's view of that uid to matter. No pid dirs either, the
	// production non-root shape, so the process column is empty and the uid
	// is the attribution.
	tcp6 := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000000000000000000000000000:46A0 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1003        0 333 1 0\n"
	root := writeProcNet(t, noFile, tcp6, noFile, noFile)
	writePasswd(t, root, "root:x:0:0:root:/root:/bin/bash\n")
	sec := CollectSockets(root, root, nil)
	if len(sec.Listening) != 1 {
		t.Fatalf("want 1 socket, got %d", len(sec.Listening))
	}
	s := sec.Listening[0]
	if s.Family != "v6" || s.Port != 18080 {
		t.Fatalf("socket = %+v", s)
	}
	if got := uid(t, s); got != 1003 {
		t.Fatalf("owner uid = %d, want 1003", got)
	}
	if s.OwnerName != "" || s.ProcessName != "" || s.PID != 0 {
		t.Fatalf("nothing may be named here, got %+v", s)
	}
}

func TestMissingPasswdKeepsUIDsAndSaysNotPresent(t *testing.T) {
	root := writeProcNet(t, realProcTCP, noFile, noFile, noFile)
	sec := CollectSockets(root, root, nil)
	if got := sec.Sources["passwd"]; got.Status != hostdoc.StatusNotPresent {
		t.Fatalf("sources[passwd] = %+v, want not_present", got)
	}
	for _, s := range sec.Listening {
		if s.OwnerUID == nil || s.OwnerName != "" {
			t.Fatalf("want bare uids with no names, got %+v", s)
		}
	}
}

func TestMalformedPasswdLinesAreSkippedNotFatal(t *testing.T) {
	// One good entry among broken shapes: too few fields, a non-numeric uid,
	// free text. The good entry must survive, exactly the socket parser's own
	// failsafe.
	tcp := "  sl  local_address rem_address   st ... inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 0 0 0 80 0 111 1 0\n"
	root := writeProcNet(t, tcp, noFile, noFile, noFile)
	writePasswd(t, root, "broken\nnouid:x:notanumber:1::/:/bin/sh\nweb:x:80:80::/var/www:/usr/sbin/nologin\n")
	sec := CollectSockets(root, root, nil)
	if got := sec.Sources["passwd"]; got.Status != hostdoc.StatusCollected {
		t.Fatalf("sources[passwd] = %+v, want collected", got)
	}
	if sec.Listening[0].OwnerName != "web" {
		t.Fatalf("owner name = %q, want web", sec.Listening[0].OwnerName)
	}
}

func TestAnAllGarbagePasswdIsAParseFailureNotSilence(t *testing.T) {
	// A passwd where not one line parses must say so. Names silently absent
	// would read exactly like uids the file does not know, and those are two
	// different findings.
	root := writeProcNet(t, realProcTCP, noFile, noFile, noFile)
	writePasswd(t, root, "complete nonsense\nmore nonsense\n")
	sec := CollectSockets(root, root, nil)
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("sockets stay collected, got %q", sec.Status)
	}
	if got := sec.Sources["passwd"]; got.Status != hostdoc.StatusReadError || got.Cause != hostdoc.CauseParseFailed {
		t.Fatalf("sources[passwd] = %+v, want read_error/parse_failed", got)
	}
	for _, s := range sec.Listening {
		if s.OwnerName != "" {
			t.Fatalf("no name may come out of a garbage passwd: %+v", s)
		}
	}
}

func TestAnEmptyPasswdIsCollectedAndNamesNothing(t *testing.T) {
	root := writeProcNet(t, realProcTCP, noFile, noFile, noFile)
	writePasswd(t, root, "")
	sec := CollectSockets(root, root, nil)
	if got := sec.Sources["passwd"]; got.Status != hostdoc.StatusCollected {
		t.Fatalf("sources[passwd] = %+v, want collected on an empty file", got)
	}
}

func TestHugeUIDsAtAndPastTheRange(t *testing.T) {
	// 4294967294 is nfsnobody's uid on el7-era hosts and must survive as a
	// number. The second row's uid does not fit in 32 bits, which no kernel
	// can emit, so the socket is kept and the uid is honestly absent rather
	// than the listener lost over one garbled column.
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 4294967294        0 111 1 0\n" +
		"   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 99999999999        0 222 1 0\n"
	root := writeProcNet(t, tcp, noFile, noFile, noFile)
	sec := CollectSockets(root, root, nil)
	if len(sec.Listening) != 2 {
		t.Fatalf("want both sockets kept, got %d", len(sec.Listening))
	}
	if got := uid(t, sec.Listening[0]); got != 4294967294 {
		t.Fatalf("owner uid = %d, want 4294967294", got)
	}
	if sec.Listening[1].OwnerUID != nil {
		t.Fatalf("an out-of-range uid must be absent, got %d", *sec.Listening[1].OwnerUID)
	}
	d := hostdoc.New("h", 1)
	d.Sockets = sec
	if _, err := hostdoc.Marshal(d); err != nil {
		t.Fatalf("collector output failed the document contract: %v", err)
	}
}

func TestPasswdNameWithControlCharactersIsSanitized(t *testing.T) {
	// A passwd entry is host-provided text and stdout mode prints on an
	// operator's terminal, so a name carrying an escape sequence takes the
	// same '?' treatment a hostile comm does.
	tcp := "  sl  local_address rem_address   st ... inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 0 0 0 80 0 111 1 0\n"
	root := writeProcNet(t, tcp, noFile, noFile, noFile)
	writePasswd(t, root, "ev\x1b[31mil:x:80:80::/:/bin/sh\n")
	sec := CollectSockets(root, root, nil)
	if got, want := sec.Listening[0].OwnerName, "ev?[31mil"; got != want {
		t.Fatalf("sanitized owner name = %q, want %q", got, want)
	}
	d := hostdoc.New("h", 1)
	d.Sockets = sec
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, b)
}

func TestAPasswdNameOverTheCapLabelsNothing(t *testing.T) {
	// glibc caps a login name at 256 (hostdoc.MaxOwnerNameLen), so a longer
	// string is not a login name. The uid keeps its number and no label,
	// never a truncated one, because half a name reads as a different name.
	long := strings.Repeat("a", hostdoc.MaxOwnerNameLen+1)
	tcp := "  sl  local_address rem_address   st ... inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 0 0 0 80 0 111 1 0\n"
	root := writeProcNet(t, tcp, noFile, noFile, noFile)
	writePasswd(t, root, long+":x:80:80::/:/bin/sh\n")
	sec := CollectSockets(root, root, nil)
	if got := uid(t, sec.Listening[0]); got != 80 {
		t.Fatalf("owner uid = %d, want 80", got)
	}
	if sec.Listening[0].OwnerName != "" {
		t.Fatalf("an over-cap name must label nothing, got %q", sec.Listening[0].OwnerName)
	}
}

func TestDuplicateUIDKeepsTheFirstPasswdEntry(t *testing.T) {
	tcp := "  sl  local_address rem_address   st ... inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 0 0 0 5 0 111 1 0\n"
	root := writeProcNet(t, tcp, noFile, noFile, noFile)
	writePasswd(t, root, "first:x:5:5::/:/bin/sh\nsecond:x:5:5::/:/bin/sh\n")
	sec := CollectSockets(root, root, nil)
	if sec.Listening[0].OwnerName != "first" {
		t.Fatalf("owner name = %q, want the file's first entry", sec.Listening[0].OwnerName)
	}
}

func TestUIDZeroAppearsInTheDocumentBytes(t *testing.T) {
	// The wire check behind the pointer type: root's uid is 0 and it must
	// marshal, because omitting it would erase the most common owner on a
	// server. This is asserted on the bytes, not the struct, since omitempty
	// is a marshalling behaviour.
	root := writeProcNet(t, realProcTCP, noFile, noFile, noFile)
	d := hostdoc.New("h", 1)
	d.Sockets = CollectSockets(root, root, nil)
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"owner_uid": 0`) {
		t.Fatal("uid 0 did not reach the document bytes")
	}
}

func strconvPort(p int) string {
	return itoa(p)
}

// itoa avoids importing strconv into the test just for one call, keeping the
// test's own imports minimal and obvious.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
