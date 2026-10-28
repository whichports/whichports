package collect

// The socket-unit collector's review.
//
// Where the fixtures come from. Both were read off the fleet on 2026-08-19 with
// `cat`, as an ordinary user, and committed with only the noise trimmed:
//
//	ubuntu-socketunits  Ubuntu 24.04.4 LTS, systemd 255. ssh.socket is verbatim
//	                    including BindIPv6Only=ipv6-only, which is why the v6
//	                    entry may not be read as covering v4 either way.
//	                    systemd-journald-dev-log.socket and
//	                    systemd-journald@.socket are verbatim apart from
//	                    dropped licence comment lines, and they are the real
//	                    examples of an explicit Service= and of a template.
//	                    **Re-checked on 2026-08-21 against the live host** and
//	                    they were not: three directives were missing from
//	                    dev-log and journald@ differed by six, including a
//	                    ListenDatagram= line, which is the one kind of
//	                    directive this collector exists to read. Both were
//	                    replaced with the real content. The SPDX line and the
//	                    "part of systemd" line are kept, only the licence body
//	                    is trimmed, which is what "dropped licence comment
//	                    lines" means here.
//	                    Constructed on top: the /etc drop-in that resets the
//	                    address list, and masked.socket as a symlink to
//	                    /dev/null. The sockets.target.wants symlink is the
//	                    shape the host really has, pointed inside the fixture
//	                    so it resolves.
//	alma-socketunits    AlmaLinux 10.2. cockpit.socket is verbatim and carries
//	                    the bare port this whole section is careful about.
//	                    cockpit-wsinstance-https@.socket is verbatim apart from
//	                    two comment lines. The /etc/systemd/system/cockpit.socket
//	                    override is constructed, because precedence needs two
//	                    files with one name and no host had that.
//
// Everything hostile is built in a temp directory instead of committed, so the
// bytes a test depends on are visible in the test.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

const ubuntuSocketUnits = "testdata/fsroots/ubuntu-socketunits"
const almaSocketUnits = "testdata/fsroots/alma-socketunits"

// unitNamed returns the one unit with this name, failing when there is not
// exactly one.
func unitNamed(t *testing.T, sec *hostdoc.SocketUnitsSection, name string) hostdoc.SocketUnit {
	t.Helper()
	var found []hostdoc.SocketUnit
	for _, u := range sec.Units {
		if u.Name == name {
			found = append(found, u)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s, got %d: %+v", name, len(found), found)
	}
	return found[0]
}

// writeUnitFile writes one file under root, creating its directories.
func writeUnitFile(t *testing.T, root, rel, body string) string {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// collectOneUnit writes a single vendor unit file into a temp root and returns
// the entry for it, which is the shape most of the edge-case tests need.
func collectOneUnit(t *testing.T, name, body string) hostdoc.SocketUnit {
	t.Helper()
	root := t.TempDir()
	writeUnitFile(t, root, filepath.Join("usr/lib/systemd/system", name), body)
	sec := CollectSocketUnits(root)
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	return unitNamed(t, sec, name)
}

func TestSocketUnitsUbuntuProfile(t *testing.T) {
	sec := CollectSocketUnits(ubuntuSocketUnits)
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	wantSources := map[string]hostdoc.SectionStatus{
		"etc_systemd_system":           hostdoc.StatusCollected,
		"run_systemd_system":           hostdoc.StatusNotPresent,
		"usr_local_lib_systemd_system": hostdoc.StatusNotPresent,
		"usr_lib_systemd_system":       hostdoc.StatusCollected,
	}
	for src, want := range wantSources {
		if got := sec.Sources[src].Status; got != want {
			t.Errorf("source %s = %q, want %q", src, got, want)
		}
	}
	// Load-path order: the admin directory first, then the vendor one, and
	// each directory's own files in name order.
	wantOrder := []string{
		"masked.socket",
		"ssh.socket",
		"systemd-journald-dev-log.socket",
		"systemd-journald@.socket",
	}
	if len(sec.Units) != len(wantOrder) {
		t.Fatalf("unit count = %d, want %d: %+v", len(sec.Units), len(wantOrder), sec.Units)
	}
	for i, want := range wantOrder {
		if sec.Units[i].Name != want {
			t.Errorf("units[%d] = %q, want %q", i, sec.Units[i].Name, want)
		}
	}

	ssh := unitNamed(t, sec, "ssh.socket")
	if ssh.Origin != "vendor" || ssh.File != "/usr/lib/systemd/system/ssh.socket" {
		t.Errorf("ssh.socket origin/file = %q/%q", ssh.Origin, ssh.File)
	}
	if !ssh.Parsed || !ssh.SocketSection || ssh.Masked || ssh.Template {
		t.Errorf("ssh.socket flags wrong: %+v", ssh)
	}
	if ssh.Description != "OpenBSD Secure Shell server socket" {
		t.Errorf("ssh.socket description = %q", ssh.Description)
	}
	// Both families, each with the address the file wrote, in file order.
	want := []hostdoc.SocketUnitListen{
		{Directive: "ListenStream", Value: "0.0.0.0:22", Kind: "ipv4",
			AddressSpecified: true, Address: "0.0.0.0", AddressFamily: "v4", Port: 22},
		{Directive: "ListenStream", Value: "[::]:22", Kind: "ipv6",
			AddressSpecified: true, Address: "::", AddressFamily: "v6", Port: 22},
	}
	if len(ssh.Listen) != len(want) {
		t.Fatalf("ssh.socket listen = %+v", ssh.Listen)
	}
	for i := range want {
		if ssh.Listen[i] != want[i] {
			t.Errorf("ssh.socket listen[%d] = %+v, want %+v", i, ssh.Listen[i], want[i])
		}
	}
	// BindIPv6Only decides whether that v6 socket also answers v4, so the
	// document carries what the file said and concludes nothing from it.
	if ssh.BindIPv6Only != "ipv6-only" || ssh.Accept != "no" {
		t.Errorf("ssh.socket bind/accept = %q/%q", ssh.BindIPv6Only, ssh.Accept)
	}
	// No Service= in the file, so the name comes from the manual's rule and
	// says so.
	if ssh.ServiceUnit != "ssh.service" || ssh.ServiceSource != "implied" {
		t.Errorf("ssh.socket service = %q (%q), want ssh.service (implied)",
			ssh.ServiceUnit, ssh.ServiceSource)
	}
	assertStrings(t, "ssh.socket enable_links", ssh.EnableLinks,
		[]string{"/etc/systemd/system/sockets.target.wants/ssh.socket"})

	devLog := unitNamed(t, sec, "systemd-journald-dev-log.socket")
	// The file states the service, so nothing is derived here.
	if devLog.ServiceUnit != "systemd-journald.service" || devLog.ServiceSource != "declared" {
		t.Errorf("dev-log service = %q (%q)", devLog.ServiceUnit, devLog.ServiceSource)
	}
	if len(devLog.Listen) != 1 || devLog.Listen[0].Directive != "ListenDatagram" ||
		devLog.Listen[0].Kind != "unix_path" || devLog.Listen[0].Port != 0 {
		t.Errorf("dev-log listen = %+v", devLog.Listen)
	}

	journald := unitNamed(t, sec, "systemd-journald@.socket")
	if !journald.Template {
		t.Error("systemd-journald@.socket must be marked a template")
	}
	if journald.ServiceUnit != "systemd-journald@%i.service" || journald.ServiceSource != "declared" {
		t.Errorf("journald@ service = %q (%q)", journald.ServiceUnit, journald.ServiceSource)
	}

	masked := unitNamed(t, sec, "masked.socket")
	if !masked.Masked || masked.Parsed || len(masked.Listen) != 0 {
		t.Errorf("masked.socket = %+v, want masked and unparsed", masked)
	}
	if masked.Origin != "admin" {
		t.Errorf("masked.socket origin = %q, want admin", masked.Origin)
	}

	d := hostdoc.New("h", 1)
	d.SocketUnits = sec
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatalf("the fixture must satisfy the document contract: %v", err)
	}
	assertTerminalSafe(t, b)
}

// The rule this whole section is careful about: "ListenStream=9090" names a
// port and no address. systemd.socket(5) leaves what it binds to
// BindIPv6Only= and /proc/sys/net/ipv6/bindv6only, neither of which this
// collector reads, so an address here would be an invention.
func TestSocketUnitsBarePortSpecifiesNoAddress(t *testing.T) {
	sec := CollectSocketUnits(almaSocketUnits)
	var vendor hostdoc.SocketUnit
	for _, u := range sec.Units {
		if u.Name == "cockpit.socket" && u.Origin == "vendor" {
			vendor = u
		}
	}
	if len(vendor.Listen) != 1 {
		t.Fatalf("vendor cockpit.socket listen = %+v", vendor.Listen)
	}
	got := vendor.Listen[0]
	want := hostdoc.SocketUnitListen{
		Directive: "ListenStream", Value: "9090", Kind: "port_only", Port: 9090,
	}
	if got != want {
		t.Fatalf("bare port = %+v, want %+v", got, want)
	}
	if got.AddressSpecified {
		t.Error("a bare port specifies no address")
	}
	if got.Address != "" || got.AddressFamily != "" {
		t.Errorf("a bare port must claim no address and no family, got %q/%q",
			got.Address, got.AddressFamily)
	}
	// And the marshaller refuses the invented form even if a future change
	// produces it.
	d := hostdoc.New("h", 1)
	d.SocketUnits = sec
	if _, err := hostdoc.Marshal(d); err != nil {
		t.Fatalf("the honest form must marshal: %v", err)
	}
	invented := *sec
	invented.Units = []hostdoc.SocketUnit{{
		Name: "cockpit.socket", File: "/x", Origin: "vendor", Parsed: true,
		Listen: []hostdoc.SocketUnitListen{{
			Directive: "ListenStream", Value: "9090", Kind: "port_only", Port: 9090,
			Address: "0.0.0.0", AddressSpecified: true, AddressFamily: "v4",
		}},
	}}
	d.SocketUnits = &invented
	if _, err := hostdoc.Marshal(d); err == nil {
		t.Fatal("a bare port claiming 0.0.0.0 must not leave the host")
	}
}

// Two files, one unit name. Both are reported with their origin and their
// path, in load-path order, and neither is dropped: applying the override rule
// is a conclusion, and firewalld's zones already set that precedent.
func TestSocketUnitsPrecedenceOrderKeepsBothFiles(t *testing.T) {
	sec := CollectSocketUnits(almaSocketUnits)
	var cockpit []hostdoc.SocketUnit
	for _, u := range sec.Units {
		if u.Name == "cockpit.socket" {
			cockpit = append(cockpit, u)
		}
	}
	if len(cockpit) != 2 {
		t.Fatalf("want both cockpit.socket files, got %+v", cockpit)
	}
	if cockpit[0].Origin != "admin" || cockpit[0].File != "/etc/systemd/system/cockpit.socket" {
		t.Errorf("the admin file must come first, got %+v", cockpit[0])
	}
	if cockpit[1].Origin != "vendor" || cockpit[1].File != "/usr/lib/systemd/system/cockpit.socket" {
		t.Errorf("the vendor file must come second, got %+v", cockpit[1])
	}
	// The two disagree about the address, which is the point of reporting
	// both: the admin file binds loopback, the vendor file names a bare port.
	if cockpit[0].Listen[0].Address != "127.0.0.1" || cockpit[0].Listen[0].AddressFamily != "v4" {
		t.Errorf("admin cockpit listen = %+v", cockpit[0].Listen)
	}
	if cockpit[1].Listen[0].Kind != "port_only" {
		t.Errorf("vendor cockpit listen = %+v", cockpit[1].Listen)
	}
}

// A template file is not a listener. It is reported, flagged, and its
// addresses are never resolved: "%i" is runtime state, not a file.
func TestSocketUnitsTemplateIsFlaggedAndNotResolved(t *testing.T) {
	sec := CollectSocketUnits(almaSocketUnits)
	tmpl := unitNamed(t, sec, "cockpit-wsinstance-https@.socket")
	if !tmpl.Template {
		t.Error("a name ending in @.socket is a template")
	}
	if len(tmpl.Listen) != 1 || tmpl.Listen[0].Kind != "unix_path" || tmpl.Listen[0].Port != 0 {
		t.Fatalf("template listen = %+v", tmpl.Listen)
	}
	if !strings.Contains(tmpl.Listen[0].Value, "%i") {
		t.Errorf("the template's address must be carried verbatim, got %q", tmpl.Listen[0].Value)
	}
	// A specifier where a port would go is reported as a specifier, never as
	// a port.
	u := collectOneUnit(t, "guess@.socket", "[Socket]\nListenStream=%i\n")
	if len(u.Listen) != 1 {
		t.Fatalf("listen = %+v", u.Listen)
	}
	if u.Listen[0].Kind != "specifier" || u.Listen[0].Port != 0 || u.Listen[0].AddressSpecified {
		t.Errorf("%%i must be a specifier with no port and no address, got %+v", u.Listen[0])
	}
	// The implied service for a template socket is the same-named template.
	if u.ServiceUnit != "guess@.service" || u.ServiceSource != "implied" {
		t.Errorf("template service = %q (%q)", u.ServiceUnit, u.ServiceSource)
	}
}

// Drop-ins are detected and reported, not merged. The unit's own address list
// is what the document shows, and "incomplete" says plainly that the drop-in
// was not applied. The fixture's drop-in resets the list and asks for 2222, so
// a merging collector would report 2222 and this one must not.
func TestSocketUnitsDropInsAreFlaggedNotMerged(t *testing.T) {
	sec := CollectSocketUnits(ubuntuSocketUnits)
	ssh := unitNamed(t, sec, "ssh.socket")
	assertStrings(t, "ssh.socket drop_ins", ssh.DropIns,
		[]string{"/etc/systemd/system/ssh.socket.d/10-listen.conf"})
	assertStrings(t, "ssh.socket incomplete", ssh.Incomplete, []string{"drop_ins"})
	for _, l := range ssh.Listen {
		if l.Port == 2222 {
			t.Fatal("the drop-in's port must not be reported as the unit's")
		}
	}
	if len(ssh.Listen) != 2 {
		t.Fatalf("the unit file's own two addresses must survive: %+v", ssh.Listen)
	}
}

// The dashed-prefix directory and the top-level socket.d both apply to a unit,
// and both make its address list possibly incomplete.
func TestSocketUnitsPrefixAndTypeDropInsAreFound(t *testing.T) {
	root := t.TempDir()
	writeUnitFile(t, root, "usr/lib/systemd/system/foo-bar-baz.socket",
		"[Socket]\nListenStream=8080\n")
	writeUnitFile(t, root, "etc/systemd/system/foo-.socket.d/10-common.conf",
		"[Socket]\nFreeBind=yes\n")
	writeUnitFile(t, root, "etc/systemd/system/foo-bar-.socket.d/20-closer.conf",
		"[Socket]\nFreeBind=yes\n")
	writeUnitFile(t, root, "usr/lib/systemd/system/socket.d/50-all.conf",
		"[Socket]\nFreeBind=yes\n")
	// A prefix that does not match must not attach.
	writeUnitFile(t, root, "etc/systemd/system/other-.socket.d/10-no.conf",
		"[Socket]\nFreeBind=yes\n")

	sec := CollectSocketUnits(root)
	u := unitNamed(t, sec, "foo-bar-baz.socket")
	// The prefix directories match this unit by name, so they belong to it.
	assertStrings(t, "drop_ins", u.DropIns, []string{
		"/etc/systemd/system/foo-.socket.d/10-common.conf",
		"/etc/systemd/system/foo-bar-.socket.d/20-closer.conf",
	})
	// The top-level socket.d applies to every unit on the host, so it is
	// reported once on the section rather than copied onto each one. Copying
	// it made the document grow as the square of the host.
	assertStrings(t, "type_drop_ins", sec.TypeDropIns, []string{
		"/usr/lib/systemd/system/socket.d/50-all.conf",
	})
	// It still applies here, so the unit still says its list may be partial.
	// That is the whole point of moving the list without moving the warning.
	assertStrings(t, "incomplete", u.Incomplete, []string{"drop_ins"})
}

// A unit with no drop-ins of its own is still marked when a top-level
// socket.d exists, because those apply to every socket unit on the host.
func TestSocketUnitsATopLevelDropInStillMarksAUnitWithNoneOfItsOwn(t *testing.T) {
	root := t.TempDir()
	writeUnitFile(t, root, "usr/lib/systemd/system/lone.socket",
		"[Socket]\nListenStream=8081\n")
	writeUnitFile(t, root, "usr/lib/systemd/system/socket.d/50-all.conf",
		"[Socket]\nFreeBind=yes\n")

	sec := CollectSocketUnits(root)
	u := unitNamed(t, sec, "lone.socket")
	if len(u.DropIns) != 0 {
		t.Errorf("drop_ins = %v, want none of its own", u.DropIns)
	}
	assertStrings(t, "type_drop_ins", sec.TypeDropIns, []string{
		"/usr/lib/systemd/system/socket.d/50-all.conf",
	})
	assertStrings(t, "incomplete", u.Incomplete, []string{"drop_ins"})
}

// An empty assignment inside the unit file resets the address list, and
// "prior uses of any of these options will have no effect", the datagram
// entries above it included.
func TestSocketUnitsEmptyAssignmentResetsTheList(t *testing.T) {
	u := collectOneUnit(t, "reset.socket", strings.Join([]string{
		"[Socket]",
		"ListenStream=1111",
		"ListenDatagram=2222",
		"ListenStream=",
		"ListenStream=3333",
		"",
	}, "\n"))
	if !u.ListenReset {
		t.Error("the reset must be recorded")
	}
	if len(u.Listen) != 1 || u.Listen[0].Port != 3333 {
		t.Fatalf("listen = %+v, want only port 3333", u.Listen)
	}
	// The reset is a documented rule, so it is applied rather than flagged.
	if len(u.Incomplete) != 0 {
		t.Errorf("incomplete = %v, want none", u.Incomplete)
	}
}

// An empty assignment to ANY Listen directive resets the list, including the
// five the manual does not describe a reset for.
//
// This test used to assert the opposite, and the reasoning behind that was
// sound but incomplete. systemd.socket(5) states the reset only under
// ListenStream=, ListenDatagram= and ListenSequentialPacket=, so an earlier
// version flagged the other five as `listen_reset_undocumented` rather than
// guess. The manual really is silent. The manager is not: measured against a
// running systemd 257 on 2026-08-21, a unit reading ListenStream=6101, then
// the named directive assigned empty, then ListenStream=6201, reports
// `Listen=[::]:6201` and nothing else. That was tried for all eight
// directives with the same result every time.
//
// So the port before the reset does not exist, and reporting it was reporting
// a port systemd will never bind. Observed behaviour outranks the manual's
// silence.
func TestSocketUnitsAnEmptyListenDirectiveResetsTheList(t *testing.T) {
	u := collectOneUnit(t, "fifo.socket", strings.Join([]string{
		"[Socket]",
		"ListenStream=4444",
		"ListenFIFO=",
		"ListenStream=5555",
		"",
	}, "\n"))
	if !u.ListenReset {
		t.Error("the reset must be recorded")
	}
	if len(u.Listen) != 1 || u.Listen[0].Port != 5555 {
		t.Fatalf("listen = %+v, want only port 5555", u.Listen)
	}
	// Nothing is guessed at any more, so nothing is flagged.
	assertStrings(t, "incomplete", u.Incomplete, nil)
}

// A directive that cannot be an internet socket is still recorded, because a
// unit that declares one is not a unit that declaring nothing. Dropping these
// made fifteen real units across the fleet read as empty.
func TestSocketUnitsANonInternetListenerIsRecordedNotDropped(t *testing.T) {
	u := collectOneUnit(t, "f.socket", strings.Join([]string{
		"[Socket]",
		"ListenFIFO=/run/f.fifo",
		"",
	}, "\n"))
	if len(u.Listen) != 1 {
		t.Fatalf("listen = %+v, want the FIFO recorded", u.Listen)
	}
	got := u.Listen[0]
	if got.Directive != "ListenFIFO" || got.Kind != "not_an_internet_socket" {
		t.Errorf("listen[0] = %+v", got)
	}
	// Claiming neither a port nor a family, because it has neither.
	if got.Port != 0 || got.AddressFamily != "" || got.AddressSpecified {
		t.Errorf("a FIFO must claim no port and no family, got %+v", got)
	}
}

// Accept= decides which naming rule applies, and an Accept= this collector
// cannot read leaves the service unknown rather than assumed.
func TestSocketUnitsServiceNaming(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantUnit    string
		wantSource  string
		wantAcceptV string
	}{
		{"implied by default", "[Socket]\nListenStream=1\n", "svc.service", "implied", ""},
		{"implied with accept no", "[Socket]\nAccept=no\nListenStream=1\n", "svc.service", "implied", "no"},
		{"template implied with accept yes", "[Socket]\nAccept=yes\nListenStream=1\n", "svc@.service", "implied", "yes"},
		{"declared wins", "[Socket]\nService=other.service\nAccept=yes\nListenStream=1\n", "other.service", "declared", "yes"},
		{"unreadable accept", "[Socket]\nAccept=maybe\nListenStream=1\n", "", "unknown", "maybe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := collectOneUnit(t, "svc.socket", tc.body)
			if u.ServiceUnit != tc.wantUnit || u.ServiceSource != tc.wantSource {
				t.Errorf("service = %q (%q), want %q (%q)",
					u.ServiceUnit, u.ServiceSource, tc.wantUnit, tc.wantSource)
			}
			if u.Accept != tc.wantAcceptV {
				t.Errorf("accept = %q, want %q", u.Accept, tc.wantAcceptV)
			}
		})
	}
}

// A single-valued directive assigned twice is flagged, because the manual we
// read does not say which assignment systemd keeps.
func TestSocketUnitsRepeatedDirectiveIsFlagged(t *testing.T) {
	u := collectOneUnit(t, "twice.socket",
		"[Socket]\nAccept=no\nAccept=yes\nListenStream=1234\n")
	assertStrings(t, "incomplete", u.Incomplete, []string{"repeated_directive"})
}

// systemd requires a [Socket] section, so a file without one is a finding
// about the file. The read still succeeded, and it must not read as a failed
// read.
func TestSocketUnitsMissingSocketSection(t *testing.T) {
	u := collectOneUnit(t, "nosection.socket",
		"[Unit]\nDescription=nothing but a unit section\n")
	if !u.Parsed {
		t.Error("the file was read, so parsed must be true")
	}
	if u.SocketSection {
		t.Error("socket_section must be false")
	}
	if len(u.Listen) != 0 {
		t.Errorf("listen = %+v, want none", u.Listen)
	}
}

// A zero-length unit file is masked, not empty: systemd does not load it at
// all, so reporting it as a unit declaring nothing would be wrong.
func TestSocketUnitsEmptyFileIsMasked(t *testing.T) {
	u := collectOneUnit(t, "empty.socket", "")
	if !u.Masked || u.Parsed {
		t.Fatalf("empty file = %+v, want masked and unparsed", u)
	}
}

// Bytes that are not a unit file at all must come back unparsed. "Collected
// and declaring nothing" is the false all-quiet this product must never give.
func TestSocketUnitsMalformedFileIsUnparsed(t *testing.T) {
	u := collectOneUnit(t, "junk.socket", "\x00\x01 not a unit file\nnor is this\n")
	if u.Parsed {
		t.Fatalf("junk must not read as parsed: %+v", u)
	}
	if len(u.Listen) != 0 || u.SocketSection {
		t.Fatalf("junk produced content: %+v", u)
	}
}

// A file past the shared read cap is refused rather than truncated, so it
// arrives unparsed instead of as a confident answer about half a file.
func TestSocketUnitsHugeFileIsRefused(t *testing.T) {
	body := "[Socket]\nListenStream=9999\n" + strings.Repeat("# pad\n", ufwFileLimit)
	u := collectOneUnit(t, "huge.socket", body)
	if u.Parsed {
		t.Fatal("an oversized unit file must not read as parsed")
	}
	if len(u.Listen) != 0 {
		t.Fatalf("no address may be reported from a refused read: %+v", u.Listen)
	}
}

// Line continuations, including the rule that a comment block inside a
// continuation is ignored and the line joins with what follows it.
func TestSocketUnitsContinuationLines(t *testing.T) {
	u := collectOneUnit(t, "wrapped.socket", strings.Join([]string{
		"[Unit]",
		"Description=a socket with \\",
		"# an ignored comment",
		"a wrapped description",
		"",
		"[Socket]",
		"ListenStream=\\",
		"5555",
		"",
	}, "\n"))
	if u.Description != "a socket with  a wrapped description" {
		t.Errorf("description = %q", u.Description)
	}
	if len(u.Listen) != 1 || u.Listen[0].Port != 5555 || u.Listen[0].Kind != "port_only" {
		t.Fatalf("listen = %+v, want the joined bare port 5555", u.Listen)
	}
}

// Every address form the manual documents, plus the forms this collector
// refuses to interpret. A value it does not recognise is "unknown" with no
// port, never a guess.
func TestSocketUnitsAddressForms(t *testing.T) {
	cases := []struct {
		value string
		want  hostdoc.SocketUnitListen
	}{
		{"9090", hostdoc.SocketUnitListen{Kind: "port_only", Port: 9090}},
		{"0.0.0.0:22", hostdoc.SocketUnitListen{Kind: "ipv4", Address: "0.0.0.0",
			AddressSpecified: true, AddressFamily: "v4", Port: 22}},
		{"127.0.0.1:8080", hostdoc.SocketUnitListen{Kind: "ipv4", Address: "127.0.0.1",
			AddressSpecified: true, AddressFamily: "v4", Port: 8080}},
		{"[::]:22", hostdoc.SocketUnitListen{Kind: "ipv6", Address: "::",
			AddressSpecified: true, AddressFamily: "v6", Port: 22}},
		{"[2001:db8::1]:443", hostdoc.SocketUnitListen{Kind: "ipv6", Address: "2001:db8::1",
			AddressSpecified: true, AddressFamily: "v6", Port: 443}},
		{"[fe80::1]:22%eth0", hostdoc.SocketUnitListen{Kind: "ipv6", Address: "fe80::1",
			AddressSpecified: true, AddressFamily: "v6", Port: 22}},
		{"/run/some/socket", hostdoc.SocketUnitListen{Kind: "unix_path"}},
		{"@abstract", hostdoc.SocketUnitListen{Kind: "unix_abstract"}},
		{"vsock:2:1234", hostdoc.SocketUnitListen{Kind: "vsock"}},
		{"%i", hostdoc.SocketUnitListen{Kind: "specifier"}},
		{"70000", hostdoc.SocketUnitListen{Kind: "unknown"}},
		{"0", hostdoc.SocketUnitListen{Kind: "unknown"}},
		{"1.2.3.4:notaport", hostdoc.SocketUnitListen{Kind: "unknown"}},
		{"1.2.3.4", hostdoc.SocketUnitListen{Kind: "unknown"}},
		{"[not:an:address]:22", hostdoc.SocketUnitListen{Kind: "unknown"}},
		{"::1:22", hostdoc.SocketUnitListen{Kind: "unknown"}},
		{"nonsense", hostdoc.SocketUnitListen{Kind: "unknown"}},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			u := collectOneUnit(t, "forms.socket", "[Socket]\nListenStream="+tc.value+"\n")
			if len(u.Listen) != 1 {
				t.Fatalf("listen = %+v", u.Listen)
			}
			want := tc.want
			want.Directive = "ListenStream"
			want.Value = tc.value
			if u.Listen[0] != want {
				t.Fatalf("listen[0] = %+v, want %+v", u.Listen[0], want)
			}
			d := hostdoc.New("h", 1)
			d.SocketUnits = &hostdoc.SocketUnitsSection{
				Section: hostdoc.Section{Status: hostdoc.StatusCollected},
				Units:   []hostdoc.SocketUnit{u},
			}
			if _, err := hostdoc.Marshal(d); err != nil {
				t.Fatalf("every accepted form must satisfy the contract: %v", err)
			}
		})
	}
}

// ListenDatagram is UDP where ListenStream is TCP, and the directive travels
// with each entry so nothing downstream has to guess the protocol.
func TestSocketUnitsDatagramKeepsItsDirective(t *testing.T) {
	u := collectOneUnit(t, "dgram.socket", "[Socket]\nListenDatagram=0.0.0.0:69\n")
	if len(u.Listen) != 1 || u.Listen[0].Directive != "ListenDatagram" {
		t.Fatalf("listen = %+v", u.Listen)
	}
	if u.Listen[0].Port != 69 || u.Listen[0].AddressFamily != "v4" {
		t.Errorf("listen[0] = %+v", u.Listen[0])
	}
}

func TestSocketUnitsAbsentIsNotPresent(t *testing.T) {
	// A root with no systemd directories at all: every source absent, and the
	// section says not present rather than collected and empty.
	sec := CollectSocketUnits("testdata/fsroots/ubuntu-ufw")
	if sec.Status != hostdoc.StatusNotPresent {
		t.Fatalf("status = %q, want not_present", sec.Status)
	}
	if len(sec.Units) != 0 {
		t.Fatalf("units on a host with no unit directories: %+v", sec.Units)
	}
}

// A unit directory we may not list is a denial, never "no socket units here".
func TestSocketUnitsDeniedDirectoryIsADenial(t *testing.T) {
	skipIfRoot(t)
	root := t.TempDir()
	dir := filepath.Join(root, "usr/lib/systemd/system")
	writeUnitFile(t, root, "usr/lib/systemd/system/ssh.socket", "[Socket]\nListenStream=22\n")
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	sec := CollectSocketUnits(root)
	if got := sec.Sources["usr_lib_systemd_system"]; got.Status != hostdoc.StatusPermissionDenied ||
		got.Cause != hostdoc.CausePermission {
		t.Fatalf("denied directory = %+v, want permission_denied/permission", got)
	}
	if sec.Status != hostdoc.StatusPermissionDenied {
		t.Fatalf("section = %q, want permission_denied", sec.Status)
	}
}

// A unit file we may not open inside a directory we can list. The unit is
// still reported, because the file being there is evidence, and the source
// carries the denial so nobody reads "unparsed" as "broken".
func TestSocketUnitsDeniedFileIsNotSilentlyUnparsed(t *testing.T) {
	skipIfRoot(t)
	root := t.TempDir()
	path := writeUnitFile(t, root, "usr/lib/systemd/system/ssh.socket",
		"[Socket]\nListenStream=22\n")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	sec := CollectSocketUnits(root)
	if got := sec.Sources["usr_lib_systemd_system"]; got.Status != hostdoc.StatusPermissionDenied {
		t.Fatalf("source = %+v, want permission_denied", got)
	}
	u := unitNamed(t, sec, "ssh.socket")
	if u.Parsed || len(u.Listen) != 0 {
		t.Fatalf("a denied file must carry no content: %+v", u)
	}
}

// A denied .wants directory must not turn into "this unit is not enabled".
func TestSocketUnitsDeniedWantsDirectoryIsADenial(t *testing.T) {
	skipIfRoot(t)
	root := t.TempDir()
	writeUnitFile(t, root, "usr/lib/systemd/system/ssh.socket", "[Socket]\nListenStream=22\n")
	wants := filepath.Join(root, "etc/systemd/system/sockets.target.wants")
	if err := os.MkdirAll(wants, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wants, "ssh.socket"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wants, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(wants, 0o755) })

	sec := CollectSocketUnits(root)
	if got := sec.Sources["etc_systemd_system"]; got.Status != hostdoc.StatusPermissionDenied {
		t.Fatalf("source = %+v, want permission_denied", got)
	}
	u := unitNamed(t, sec, "ssh.socket")
	if len(u.EnableLinks) != 0 {
		t.Fatalf("no link may be claimed from a denied directory: %+v", u.EnableLinks)
	}
}

// Host text: a unit file name and a Description are both chosen by whoever
// wrote the file, and stdout mode prints the document on a terminal.
func TestSocketUnitsHostileTextSanitized(t *testing.T) {
	root := t.TempDir()
	writeUnitFile(t, root, "usr/lib/systemd/system/ev\x1bil.socket", strings.Join([]string{
		"[Unit]",
		"Description=bell \a and \x1b[31mcolour\x1b[0m and a C1  byte",
		"[Socket]",
		"ListenStream=22",
		"",
	}, "\n"))
	sec := CollectSocketUnits(root)
	u := unitNamed(t, sec, "ev?il.socket")
	if u.File != "/usr/lib/systemd/system/ev?il.socket" {
		t.Errorf("file = %q, want the sanitized path", u.File)
	}
	if strings.ContainsAny(u.Description, "\a\x1b") {
		t.Errorf("description kept a control character: %q", u.Description)
	}
	d := hostdoc.New("h", 1)
	d.SocketUnits = sec
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, b)
}

func TestSocketUnitsDeterministic(t *testing.T) {
	d1 := hostdoc.New("h", 1)
	d1.SocketUnits = CollectSocketUnits(ubuntuSocketUnits)
	d2 := hostdoc.New("h", 1)
	d2.SocketUnits = CollectSocketUnits(ubuntuSocketUnits)
	b1, err1 := hostdoc.Marshal(d1)
	b2, err2 := hostdoc.Marshal(d2)
	if err1 != nil || err2 != nil {
		t.Fatalf("marshal errors: %v %v", err1, err2)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("two collections of the same unit files differ")
	}
}

// Nothing in this section may read as a reachability claim. The words that
// would make it one are absent from the JSON, and this pins that.
func TestSocketUnitsSayNothingAboutListening(t *testing.T) {
	d := hostdoc.New("h", 1)
	d.SocketUnits = CollectSocketUnits(ubuntuSocketUnits)
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, word := range []string{"listening", "reachable", "open", "enabled", "active"} {
		if strings.Contains(string(b), word) {
			t.Errorf("the socket_units section must not use the word %q: a unit file is a declaration", word)
		}
	}
}

// A symlink from one unit name to another is an alias: systemd reads it as a
// second name for one unit, not as a second unit.
//
// Before this was handled, alias.socket was reported as its own unit carrying
// the same port and a service_unit of alias.service, a name that exists
// nowhere. One real port counted twice and one invented service.
func TestSocketUnitsAnAliasIsNotASecondUnit(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "usr/lib/systemd/system")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeUnitFile(t, root, "usr/lib/systemd/system/real.socket",
		"[Socket]\nListenStream=7002\n")
	if err := os.Symlink("real.socket", filepath.Join(dir, "alias.socket")); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}

	sec := CollectSocketUnits(root)
	alias := unitNamed(t, sec, "alias.socket")
	if alias.AliasOf != "real.socket" {
		t.Errorf("alias_of = %q, want real.socket", alias.AliasOf)
	}
	// The two things that made it wrong before.
	if len(alias.Listen) != 0 {
		t.Errorf("an alias must not repeat the port, got %+v", alias.Listen)
	}
	if alias.ServiceUnit != "" {
		t.Errorf("an alias must not imply a service, got %q", alias.ServiceUnit)
	}

	// The real unit still carries the port, once.
	real := unitNamed(t, sec, "real.socket")
	if len(real.Listen) != 1 || real.Listen[0].Port != 7002 {
		t.Fatalf("real.socket listen = %+v", real.Listen)
	}
	if real.ServiceUnit != "real.service" {
		t.Errorf("service_unit = %q", real.ServiceUnit)
	}
}

// Every unit says which directory it came from. Origin cannot rank two copies
// of one unit, because /etc/systemd/system and /usr/local/lib/systemd/system
// are both "admin", and a reader deciding which one systemd loads should not
// have to depend on the order of the array.
func TestSocketUnitsEveryUnitNamesItsSourceDirectory(t *testing.T) {
	root := t.TempDir()
	writeUnitFile(t, root, "etc/systemd/system/s.socket", "[Socket]\nListenStream=7003\n")
	writeUnitFile(t, root, "usr/local/lib/systemd/system/s.socket", "[Socket]\nListenStream=7004\n")
	writeUnitFile(t, root, "usr/lib/systemd/system/v.socket", "[Socket]\nListenStream=7005\n")

	sec := CollectSocketUnits(root)
	seen := map[string]string{}
	for _, u := range sec.Units {
		if u.Source == "" {
			t.Errorf("%s (%s) has no source", u.Name, u.File)
		}
		seen[u.File] = u.Source
		// Both admin directories share an origin, which is the whole point.
		if u.Source == "etc_systemd_system" || u.Source == "usr_local_lib_systemd_system" {
			if u.Origin != "admin" {
				t.Errorf("%s origin = %q, want admin", u.File, u.Origin)
			}
		}
	}
	if seen["/etc/systemd/system/s.socket"] != "etc_systemd_system" {
		t.Errorf("etc copy source = %q", seen["/etc/systemd/system/s.socket"])
	}
	if seen["/usr/local/lib/systemd/system/s.socket"] != "usr_local_lib_systemd_system" {
		t.Errorf("usr/local copy source = %q", seen["/usr/local/lib/systemd/system/s.socket"])
	}
}

// Accept=yes only names a template service when every listener can accept one.
//
// systemd does not fall back to the plain service when one cannot. It refuses
// the unit: "Unit configured for accepting sockets, but sockets are
// non-accepting. Refusing." (systemd 257, systemd-analyze verify, read
// 2026-08-21). One datagram port beside a good stream port kills the unit, so
// naming a service for it was naming something that never runs.
//
// The manual is softer than the manager. systemd.socket(5) says Accept= "is
// ignored for datagram sockets and FIFOs", which reads as a fallback to the
// plain name. The manager refuses. The manager is what runs.
func TestSocketUnitsAcceptYesNeedsListenersThatCanAccept(t *testing.T) {
	for _, tc := range []struct {
		name        string
		body        string
		wantService string
		wantSource  string
	}{
		{"stream accepts", "ListenStream=4004\nAccept=yes\n", "a@.service", "implied"},
		{"seqpacket accepts", "ListenSequentialPacket=/run/s\nAccept=yes\n", "a@.service", "implied"},
		{"datagram cannot", "ListenDatagram=4003\nAccept=yes\n", "", "unknown"},
		{"fifo cannot", "ListenFIFO=/run/f\nAccept=yes\n", "", "unknown"},
		// The one worth staring at: a usable stream port beside one datagram
		// port, and systemd refuses the whole unit.
		{"one bad listener kills it", "ListenStream=4004\nListenDatagram=4005\nAccept=yes\n", "", "unknown"},
		// Without Accept=yes none of this applies and the plain name stands.
		{"datagram without accept", "ListenDatagram=4003\n", "a.service", "implied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := collectOneUnit(t, "a.socket", "[Socket]\n"+tc.body)
			if u.ServiceUnit != tc.wantService {
				t.Errorf("service_unit = %q, want %q", u.ServiceUnit, tc.wantService)
			}
			if u.ServiceSource != tc.wantSource {
				t.Errorf("service_source = %q, want %q", u.ServiceSource, tc.wantSource)
			}
		})
	}
}

// A generated unit is a real unit. An earlier version skipped the generator
// directories because generators rewrite them at every boot, which is true and
// is not a reason: the unit is loaded and enabled right now.
//
// An AlmaLinux 10 server had /run/systemd/generator/sshd-unix-local.socket,
// read on 2026-08-21, and systemd-ssh-generator(8) writes TCP listeners into the same
// directory from the ssh.listen credential. So the port loss was one config
// line away rather than hypothetical.
func TestSocketUnitsGeneratorDirectoriesAreRead(t *testing.T) {
	root := t.TempDir()
	writeUnitFile(t, root, "run/systemd/generator/gen.socket",
		"[Socket]\nListenStream=7100\n")
	writeUnitFile(t, root, "run/systemd/generator.early/early.socket",
		"[Socket]\nListenStream=7101\n")
	writeUnitFile(t, root, "run/systemd/generator.late/late.socket",
		"[Socket]\nListenStream=7102\n")

	sec := CollectSocketUnits(root)
	for _, want := range []struct{ name, source string }{
		{"gen.socket", "run_systemd_generator"},
		{"early.socket", "run_systemd_generator_early"},
		{"late.socket", "run_systemd_generator_late"},
	} {
		u := unitNamed(t, sec, want.name)
		if u.Source != want.source {
			t.Errorf("%s source = %q, want %q", want.name, u.Source, want.source)
		}
		if u.Origin != "generator" {
			t.Errorf("%s origin = %q, want generator", want.name, u.Origin)
		}
		if len(u.Listen) != 1 {
			t.Errorf("%s listen = %+v", want.name, u.Listen)
		}
	}
}

// The load path order is the manual's, and generator.early really does outrank
// /etc. Units are reported in that order, and a reader deciding which copy
// systemd loads depends on it.
func TestSocketUnitsGeneratorEarlyOutranksEtc(t *testing.T) {
	root := t.TempDir()
	writeUnitFile(t, root, "etc/systemd/system/dup.socket", "[Socket]\nListenStream=7200\n")
	writeUnitFile(t, root, "run/systemd/generator.early/dup.socket", "[Socket]\nListenStream=7201\n")

	sec := CollectSocketUnits(root)
	var order []string
	for _, u := range sec.Units {
		if u.Name == "dup.socket" {
			order = append(order, u.Source)
		}
	}
	want := []string{"run_systemd_generator_early", "etc_systemd_system"}
	if len(order) != 2 || order[0] != want[0] || order[1] != want[1] {
		t.Errorf("order = %v, want %v", order, want)
	}
}

// Description= is the one field the manual makes free text by design, and the
// host writes it. A unit file with 200,000 characters in it used to put all
// 200,000 on the wire.
func TestSocketUnitsALongDescriptionIsCutAndSaysSo(t *testing.T) {
	long := strings.Repeat("A", 200000)
	u := collectOneUnit(t, "d.socket",
		"[Unit]\nDescription="+long+"\n[Socket]\nListenStream=1\n")
	if len(u.Description) != maxDescription {
		t.Errorf("description length = %d, want %d", len(u.Description), maxDescription)
	}
	assertStrings(t, "incomplete", u.Incomplete, []string{"description_truncated"})
}

// A description that fits is untouched and nothing is flagged, because a
// marker that fires on ordinary input is a marker people learn to ignore.
func TestSocketUnitsAnOrdinaryDescriptionIsNotTouched(t *testing.T) {
	u := collectOneUnit(t, "d.socket",
		"[Unit]\nDescription=OpenBSD Secure Shell server socket\n[Socket]\nListenStream=1\n")
	if u.Description != "OpenBSD Secure Shell server socket" {
		t.Errorf("description = %q", u.Description)
	}
	assertStrings(t, "incomplete", u.Incomplete, nil)
}

// An enabled template instance is a real unit with a real port, and it has no
// file of its own.
//
// systemd loads inst@7006.socket from the template inst@.socket, so nothing
// named inst@7006.socket exists on disk and a scan of unit files never sees
// it. It was dropped entirely, and with it a listening port: measured against
// systemd 257, this exact shape reports Listen=[::]:7006, LoadState=loaded and
// UnitFileState=enabled.
func TestSocketUnitsAnEnabledTemplateInstanceIsAUnit(t *testing.T) {
	root := t.TempDir()
	writeUnitFile(t, root, "usr/lib/systemd/system/inst@.socket",
		"[Socket]\nListenStream=%i\n")
	wants := filepath.Join(root, "etc/systemd/system/sockets.target.wants")
	if err := os.MkdirAll(wants, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/lib/systemd/system/inst@.socket",
		filepath.Join(wants, "inst@7006.socket")); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}

	sec := CollectSocketUnits(root)
	u := unitNamed(t, sec, "inst@7006.socket")
	if u.Instance != "7006" {
		t.Errorf("instance = %q, want 7006", u.Instance)
	}
	// File names the template, because that is the file systemd reads.
	if u.File != "/usr/lib/systemd/system/inst@.socket" {
		t.Errorf("file = %q", u.File)
	}
	if len(u.Listen) != 1 || u.Listen[0].Port != 7006 {
		t.Fatalf("listen = %+v, want port 7006", u.Listen)
	}
	if u.Listen[0].Kind != "port_only" {
		t.Errorf("kind = %q, want port_only", u.Listen[0].Kind)
	}
	if u.ServiceUnit != "inst@7006.service" {
		t.Errorf("service_unit = %q", u.ServiceUnit)
	}
	if len(u.EnableLinks) != 1 {
		t.Errorf("enable_links = %v", u.EnableLinks)
	}
	// The template itself is still reported, and is still not a listener.
	tmpl := unitNamed(t, sec, "inst@.socket")
	if tmpl.Instance != "" {
		t.Errorf("the template must carry no instance, got %q", tmpl.Instance)
	}
	if len(tmpl.Listen) != 1 || tmpl.Listen[0].Kind != "specifier" {
		t.Errorf("the template's %%i must stay unexpanded, got %+v", tmpl.Listen)
	}
}

// Only %i is substituted, and only because the instance name is a fact read
// off the link. Anything else stays a specifier rather than being invented.
func TestSocketUnitsAnInstanceDoesNotResolveOtherSpecifiers(t *testing.T) {
	root := t.TempDir()
	writeUnitFile(t, root, "usr/lib/systemd/system/host@.socket",
		"[Socket]\nListenStream=%H:80\n")
	wants := filepath.Join(root, "etc/systemd/system/sockets.target.wants")
	if err := os.MkdirAll(wants, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/lib/systemd/system/host@.socket",
		filepath.Join(wants, "host@a.socket")); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}

	u := unitNamed(t, CollectSocketUnits(root), "host@a.socket")
	if len(u.Listen) != 1 || u.Listen[0].Kind != "specifier" {
		t.Fatalf("%%H is runtime state and must not be resolved, got %+v", u.Listen)
	}
	if u.Listen[0].Port != 0 {
		t.Errorf("an unresolved specifier must claim no port, got %d", u.Listen[0].Port)
	}
}

// A link naming a template this host does not have is a dangling link, which
// systemd.unit(5) says is expected. Nothing is invented for it.
func TestSocketUnitsADanglingInstanceLinkInventsNoUnit(t *testing.T) {
	root := t.TempDir()
	writeUnitFile(t, root, "usr/lib/systemd/system/real.socket", "[Socket]\nListenStream=1\n")
	wants := filepath.Join(root, "etc/systemd/system/sockets.target.wants")
	if err := os.MkdirAll(wants, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/lib/systemd/system/gone@.socket",
		filepath.Join(wants, "gone@9.socket")); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}

	for _, u := range CollectSocketUnits(root).Units {
		if u.Name == "gone@9.socket" {
			t.Fatalf("invented a unit for a dangling link: %+v", u)
		}
	}
}

// A unit file that is a symlink out of the unit directories is not opened.
//
// isMaskedUnit used os.Stat and readCapped used os.Open, and both follow
// symlinks, so /etc/systemd/system/x.socket pointing anywhere made the root
// agent read that file. If it happened to parse as INI, its Description= was
// copied into the document and posted to the control plane.
//
// It needs write access to a unit directory, which normally means root
// already, so this is smaller than it sounds. It is still not a hole to leave
// open: the agent must not become a way to read a file its own reader did not
// choose.
func TestSocketUnitsASymlinkOutOfTheUnitDirectoriesIsNotRead(t *testing.T) {
	root := t.TempDir()
	// A decoy that parses cleanly and holds something that must never travel.
	writeUnitFile(t, root, "decoy/fake-shadow",
		"[Unit]\nDescription=TOP SECRET root:$6$deadbeef\n[Socket]\nListenStream=22\n")
	dir := filepath.Join(root, "etc/systemd/system")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "decoy/fake-shadow"),
		filepath.Join(dir, "secret.socket")); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}

	sec := CollectSocketUnits(root)
	u := unitNamed(t, sec, "secret.socket")
	if u.Parsed {
		t.Error("the file was opened and parsed, which is the bug")
	}
	if u.Description != "" {
		t.Errorf("the decoy's Description travelled: %q", u.Description)
	}
	if len(u.Listen) != 0 {
		t.Errorf("the decoy's ports travelled: %+v", u.Listen)
	}
	assertStrings(t, "incomplete", u.Incomplete,
		[]string{"symlink_outside_unit_directories"})

	// And nothing anywhere in the document carries the secret.
	blob, err := json.Marshal(sec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "deadbeef") {
		t.Fatal("the decoy's contents reached the document")
	}
}

// The three symlinks systemd really uses still work: /dev/null to mask, and a
// link to a unit file in another unit directory. A guard that broke those
// would be worse than the hole it closed.
func TestSocketUnitsLegitimateSymlinksStillWork(t *testing.T) {
	root := t.TempDir()
	writeUnitFile(t, root, "usr/lib/systemd/system/real.socket",
		"[Socket]\nListenStream=7300\n")
	dir := filepath.Join(root, "etc/systemd/system")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(dir, "masked.socket")); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}
	// An enable-style link across unit directories. Written relative so it
	// resolves inside the fixture: an absolute link would be read against the
	// real filesystem root and dangle, which is the same reason the committed
	// fixtures point their sockets.target.wants link inside the tree.
	if err := os.Symlink("../../../usr/lib/systemd/system/real.socket",
		filepath.Join(dir, "linked.socket")); err != nil {
		t.Skip("symlink unsupported")
	}

	sec := CollectSocketUnits(root)
	if m := unitNamed(t, sec, "masked.socket"); !m.Masked {
		t.Error("a /dev/null link must still read as masked")
	}
	if l := unitNamed(t, sec, "linked.socket"); l.AliasOf != "real.socket" {
		t.Errorf("a link to another unit file must still read as an alias, got %+v", l)
	}
}

// A two-hop symlink chain out of the unit directories is not read.
//
// The guard once resolved one hop only. A chain whose first link landed back
// inside a unit directory passed that check, and its second link pointed at any
// file on the host. os.Open in readCapped follows every hop, so it read the
// out-of-bounds file, and its Description= reached the document. The first hop
// here is a plain name (no .socket suffix) so the alias path does not catch it,
// which is what leaves readCapped to follow the whole chain.
func TestSocketUnitsATwoHopSymlinkChainOutOfBoundsIsNotRead(t *testing.T) {
	root := t.TempDir()
	// The file at the end of the chain, out of the unit directories, holding
	// something that must never travel.
	writeUnitFile(t, root, "decoy/fake-shadow",
		"[Unit]\nDescription=TOP SECRET root:$6$c0ffee\n[Socket]\nListenStream=22\n")
	dir := filepath.Join(root, "etc/systemd/system")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Second hop: an in-directory intermediate that points out of the tree.
	if err := os.Symlink(filepath.Join(root, "decoy/fake-shadow"),
		filepath.Join(dir, "hop")); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}
	// First hop: the unit file, pointing at the intermediate beside it. This
	// hop resolves inside the unit directory, which is what fooled the one-hop
	// guard.
	if err := os.Symlink("hop", filepath.Join(dir, "leak.socket")); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}

	sec := CollectSocketUnits(root)
	u := unitNamed(t, sec, "leak.socket")
	if u.Parsed {
		t.Error("the file at the end of the chain was opened and parsed, which is the bug")
	}
	if u.Description != "" {
		t.Errorf("the decoy's Description travelled: %q", u.Description)
	}
	if len(u.Listen) != 0 {
		t.Errorf("the decoy's ports travelled: %+v", u.Listen)
	}
	assertStrings(t, "incomplete", u.Incomplete,
		[]string{"symlink_outside_unit_directories"})

	blob, err := json.Marshal(sec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "c0ffee") {
		t.Fatal("the decoy's contents reached the document")
	}
}

// A two-hop symlink chain that stays inside the unit directories is read.
//
// systemctl enable makes symlinked aliases of real units, and a distribution or
// an administrator can stack a second link on top, so a multi-hop chain that
// lands on a real unit file inside the tree is normal and must be read. The
// intermediate here is a plain name so the chain is followed to content rather
// than reported as an alias.
func TestSocketUnitsATwoHopSymlinkChainInsideIsRead(t *testing.T) {
	root := t.TempDir()
	writeUnitFile(t, root, "usr/lib/systemd/system/backing.socket",
		"[Socket]\nListenStream=8200\n")
	dir := filepath.Join(root, "etc/systemd/system")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Second hop: an in-directory intermediate pointing at the real unit file
	// in another unit directory. Written relative so it resolves inside the
	// fixture rather than against the real filesystem root.
	if err := os.Symlink("../../../usr/lib/systemd/system/backing.socket",
		filepath.Join(dir, "entry.real")); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}
	// First hop: the unit file pointing at the intermediate beside it.
	if err := os.Symlink("entry.real", filepath.Join(dir, "entry.socket")); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}

	u := unitNamed(t, CollectSocketUnits(root), "entry.socket")
	if !u.Parsed {
		t.Fatalf("a chain that stays inside the unit directories must be read, got %+v", u)
	}
	if len(u.Listen) != 1 || u.Listen[0].Port != 8200 {
		t.Errorf("listen = %+v, want port 8200", u.Listen)
	}
	for _, r := range u.Incomplete {
		if r == "symlink_outside_unit_directories" {
			t.Error("an in-bounds chain must not be marked as escaping")
		}
	}
}

// A symlink loop is refused rather than followed. filepath.EvalSymlinks returns
// an error for a cycle, and the collector treats that as a chain it cannot
// prove is in bounds, so it opens nothing and marks the unit.
func TestSocketUnitsASymlinkLoopIsRefused(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/systemd/system")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loopb", filepath.Join(dir, "loop.socket")); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}
	if err := os.Symlink("loop.socket", filepath.Join(dir, "loopb")); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}

	u := unitNamed(t, CollectSocketUnits(root), "loop.socket")
	if u.Parsed {
		t.Error("a symlink loop must not be followed")
	}
	assertStrings(t, "incomplete", u.Incomplete,
		[]string{"symlink_outside_unit_directories"})
}

// A broken link that resolves nowhere is refused and marked. Its first hop
// lands inside a unit directory, so the one-hop guard passed it and left it
// unmarked, which is the silent narrowing the design forbids: a unit that was
// refused must say so.
func TestSocketUnitsABrokenSymlinkIsRefusedAndMarked(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/systemd/system")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Points at a name beside it that does not exist. filepath.Join keeps it
	// inside the unit directory, so the old one-hop check saw nothing wrong.
	if err := os.Symlink("nope", filepath.Join(dir, "broken.socket")); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}

	u := unitNamed(t, CollectSocketUnits(root), "broken.socket")
	if u.Parsed {
		t.Error("a broken link resolves to no file and must not read as parsed")
	}
	assertStrings(t, "incomplete", u.Incomplete,
		[]string{"symlink_outside_unit_directories"})
}
