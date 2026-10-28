package collect

// The pure half of the unit-name reader (sockdiag.go): the request bytes, the
// reply parser against hand-built kernel messages, the cgroup walk against a
// directory tree, and the join into the sockets section. No netlink socket is
// opened here; sockdiag_linux_test.go opens the real one, on Linux only.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// diagEntry is one socket in a hand-built reply.
type diagEntry struct {
	inode    uint32
	cgroupID uint64
	// withID says whether the INET_DIAG_CGROUP_ID attribute is present at
	// all, which a kernel before 5.8 never sends.
	withID bool
	// withPad puts an INET_DIAG_PAD attribute before the id, which is what
	// nla_put_u64_64bit does to align the u64 in a real reply.
	withPad bool
	// typeFlags are ORed into the attribute type, the two high bits the
	// kernel may set and a parser must mask off.
	typeFlags uint16
}

func nlmsg(msgType, flags uint16, seq uint32, payload []byte) []byte {
	b := make([]byte, nlmsgHdrLen, nlmsgHdrLen+len(payload)+4)
	nativeEndian.PutUint32(b[0:4], uint32(nlmsgHdrLen+len(payload)))
	nativeEndian.PutUint16(b[4:6], msgType)
	nativeEndian.PutUint16(b[6:8], flags)
	nativeEndian.PutUint32(b[8:12], seq)
	b = append(b, payload...)
	for len(b)%nlaAlignTo != 0 {
		b = append(b, 0)
	}
	return b
}

func nlattr(attrType uint16, value []byte) []byte {
	b := make([]byte, nlaHdrLen, nlaHdrLen+len(value)+4)
	nativeEndian.PutUint16(b[0:2], uint16(nlaHdrLen+len(value)))
	nativeEndian.PutUint16(b[2:4], attrType)
	b = append(b, value...)
	for len(b)%nlaAlignTo != 0 {
		b = append(b, 0)
	}
	return b
}

func diagMessage(e diagEntry) []byte {
	msg := make([]byte, inetDiagMsgLen)
	msg[0] = afInet
	msg[1] = tcpListen
	nativeEndian.PutUint32(msg[inetDiagInodeOff:], e.inode)
	if e.withPad {
		msg = append(msg, nlattr(14, nil)...) // INET_DIAG_PAD, empty
	}
	if e.withID {
		id := make([]byte, 8)
		nativeEndian.PutUint64(id, e.cgroupID)
		msg = append(msg, nlattr(inetDiagCgroupID|e.typeFlags, id)...)
	}
	return msg
}

// diagReply is a whole dump as the kernel sends it: the sockets, then DONE.
func diagReply(seq uint32, entries ...diagEntry) []byte {
	var b []byte
	for _, e := range entries {
		b = append(b, nlmsg(sockDiagByFamily, nlmFMulti, seq, diagMessage(e))...)
	}
	return append(b, nlmsg(nlmsgDone, nlmFMulti, seq, make([]byte, 4))...)
}

// --------------------------------------------------------------- request

func TestEncodeDiagRequestIsTheKernelsLayout(t *testing.T) {
	b := encodeDiagRequest(diagRequest{afInet6, ipprotoTCP, 1 << tcpListen, 7})
	if len(b) != nlmsgHdrLen+inetDiagReqLen {
		t.Fatalf("request is %d bytes, want %d", len(b), nlmsgHdrLen+inetDiagReqLen)
	}
	if got := nativeEndian.Uint32(b[0:4]); got != uint32(len(b)) {
		t.Errorf("nlmsg_len = %d, want %d", got, len(b))
	}
	if got := nativeEndian.Uint16(b[4:6]); got != sockDiagByFamily {
		t.Errorf("nlmsg_type = %d, want SOCK_DIAG_BY_FAMILY %d", got, sockDiagByFamily)
	}
	if got := nativeEndian.Uint16(b[6:8]); got != nlmFRequest|nlmFDump {
		t.Errorf("nlmsg_flags = %#x, want REQUEST|DUMP %#x", got, nlmFRequest|nlmFDump)
	}
	if got := nativeEndian.Uint32(b[8:12]); got != 7 {
		t.Errorf("nlmsg_seq = %d, want 7", got)
	}
	if b[16] != afInet6 || b[17] != ipprotoTCP || b[18] != 0 || b[19] != 0 {
		t.Errorf("family/protocol/ext/pad = %v, want [10 6 0 0]", b[16:20])
	}
	if got := nativeEndian.Uint32(b[20:24]); got != 1<<tcpListen {
		t.Errorf("idiag_states = %#x, want 1<<TCP_LISTEN", got)
	}
	for i, v := range b[24:] {
		if v != 0 {
			t.Fatalf("socket id byte %d is %d, want an empty id so the dump is unfiltered", i, v)
		}
	}
}

func TestTheFourDumpsMatchTheFourProcNetTables(t *testing.T) {
	if len(diagRequests) != len(procNetSources) {
		t.Fatalf("%d dumps for %d /proc/net tables", len(diagRequests), len(procNetSources))
	}
	seen := map[uint32]bool{}
	for _, r := range diagRequests {
		if seen[r.seq] {
			t.Errorf("sequence %d is used twice, so replies could be misfiled", r.seq)
		}
		seen[r.seq] = true
		if r.protocol == ipprotoTCP && r.states != 1<<tcpListen {
			t.Errorf("a TCP dump asks for states %#x, want listening only", r.states)
		}
		if r.protocol == ipprotoUDP && r.states != allStates {
			t.Errorf("a UDP dump asks for states %#x, want every state", r.states)
		}
	}
}

// ----------------------------------------------------------------- parser

func TestParseDiagReplyReadsInodeAndCgroupID(t *testing.T) {
	b := diagReply(1,
		diagEntry{inode: 12345, cgroupID: 0xabc, withID: true},
		diagEntry{inode: 67890, cgroupID: 0xdef, withID: true, withPad: true},
		diagEntry{inode: 111, cgroupID: 0x1, withID: true, typeFlags: 1 << 15})
	byInode := map[uint32]uint64{}
	done, err := parseDiagReply(b, 1, byInode)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v, want done and no error", done, err)
	}
	want := map[uint32]uint64{12345: 0xabc, 67890: 0xdef, 111: 0x1}
	if len(byInode) != len(want) {
		t.Fatalf("got %v, want %v", byInode, want)
	}
	for inode, id := range want {
		if byInode[inode] != id {
			t.Errorf("inode %d: cgroup id %#x, want %#x", inode, byInode[inode], id)
		}
	}
}

func TestAMessageWithoutTheAttributeIsAbsentNotZero(t *testing.T) {
	// What a kernel before 5.8 sends: the socket, and no cgroup id at all.
	b := diagReply(1, diagEntry{inode: 12345, withID: false})
	byInode := map[uint32]uint64{}
	done, err := parseDiagReply(b, 1, byInode)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if _, present := byInode[12345]; present {
		t.Fatalf("an inode with no cgroup id was recorded as %v", byInode)
	}
}

func TestAnotherSequenceIsSkippedNotMisfiled(t *testing.T) {
	b := diagReply(2, diagEntry{inode: 1, cgroupID: 9, withID: true})
	byInode := map[uint32]uint64{}
	done, err := parseDiagReply(b, 1, byInode)
	if err != nil || done {
		t.Fatalf("done=%v err=%v, want neither: nothing here was ours", done, err)
	}
	if len(byInode) != 0 {
		t.Fatalf("recorded %v from another request's reply", byInode)
	}
}

func TestAnErrorMessageEndsTheDumpWithItsErrno(t *testing.T) {
	payload := make([]byte, 4)
	var errno int32 = -2 // -ENOENT, as struct nlmsgerr carries it
	nativeEndian.PutUint32(payload, uint32(errno))
	b := nlmsg(nlmsgError, 0, 1, payload)
	byInode := map[uint32]uint64{}
	_, err := parseDiagReply(b, 1, byInode)
	var dumpErr errDiagDump
	if !errors.As(err, &dumpErr) || dumpErr.errno != 2 {
		t.Fatalf("err = %v, want errDiagDump with errno 2", err)
	}
	if strings.Contains(err.Error(), "2") {
		t.Errorf("the error text carries the errno, which must stay out of any document: %q", err)
	}
}

func TestAnAcknowledgementIsNotAnError(t *testing.T) {
	b := nlmsg(nlmsgError, 0, 1, make([]byte, 4)) // errno 0
	b = append(b, diagReply(1, diagEntry{inode: 5, cgroupID: 6, withID: true})...)
	byInode := map[uint32]uint64{}
	done, err := parseDiagReply(b, 1, byInode)
	if err != nil || !done || byInode[5] != 6 {
		t.Fatalf("done=%v err=%v got=%v", done, err, byInode)
	}
}

func TestTruncatedRepliesAreMalformedAndNeverRead(t *testing.T) {
	good := diagReply(1, diagEntry{inode: 12345, cgroupID: 1, withID: true})
	cases := map[string][]byte{
		"short header":        good[:8],
		"length past buffer":  good[:len(good)-8],
		"length below header": func() []byte { b := append([]byte{}, good...); nativeEndian.PutUint32(b[0:4], 4); return b }(),
	}
	for name, b := range cases {
		byInode := map[uint32]uint64{}
		_, err := parseDiagReply(b, 1, byInode)
		if !errors.Is(err, errDiagMalformed) {
			t.Errorf("%s: err = %v, want errDiagMalformed", name, err)
		}
	}
}

func TestATruncatedAttributeDropsThatSocketOnly(t *testing.T) {
	msg := diagMessage(diagEntry{inode: 7, cgroupID: 8, withID: true})
	msg = msg[:len(msg)-4] // cut into the attribute value
	b := nlmsg(sockDiagByFamily, nlmFMulti, 1, msg)
	b = append(b, diagReply(1, diagEntry{inode: 9, cgroupID: 10, withID: true})...)
	byInode := map[uint32]uint64{}
	done, err := parseDiagReply(b, 1, byInode)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if _, present := byInode[7]; present {
		t.Errorf("a socket whose attribute was cut short was recorded")
	}
	if byInode[9] != 10 {
		t.Errorf("the socket after it was lost: %v", byInode)
	}
}

func TestAReplyWithoutTheMultiFlagIsCompleteOnItsOwn(t *testing.T) {
	b := nlmsg(sockDiagByFamily, 0, 1, diagMessage(diagEntry{inode: 1, cgroupID: 2, withID: true}))
	byInode := map[uint32]uint64{}
	done, err := parseDiagReply(b, 1, byInode)
	if err != nil || !done || byInode[1] != 2 {
		t.Fatalf("done=%v err=%v got=%v", done, err, byInode)
	}
}

func FuzzParseDiagReply(f *testing.F) {
	f.Add(diagReply(1, diagEntry{inode: 12345, cgroupID: 0xabc, withID: true, withPad: true}), uint32(1))
	f.Add(nlmsg(nlmsgError, 0, 1, []byte{0xfe, 0xff, 0xff, 0xff}), uint32(1))
	f.Add([]byte("\x00\xff\x1b[31m"), uint32(1))
	f.Fuzz(func(t *testing.T, data []byte, seq uint32) {
		// The property is the collector contract: never panic, never read
		// past the buffer, and whatever is accepted joins into a document
		// that marshals.
		byInode := map[uint32]uint64{}
		_, _ = parseDiagReply(data, seq, byInode)
		byID := map[uint64]string{}
		for _, id := range byInode {
			byID[id] = "/system.slice/x.service"
		}
		joined := joinCgroups(byInode, byID)
		listening := make([]hostdoc.ListeningSocket, 0, len(joined))
		for _, inode := range sortedInodes(joined) {
			listening = append(listening, hostdoc.ListeningSocket{
				Protocol: "tcp", Family: "v4", BindAddress: "0.0.0.0", Port: 1,
				Cgroup: joined[inode], Unit: unitOfCgroup(joined[inode])})
		}
		marshalOrFail(t, func(d *hostdoc.Document) {
			d.Sockets = &hostdoc.SocketsSection{
				Section:   hostdoc.Section{Status: hostdoc.StatusCollected},
				Listening: listening,
			}
		})
	})
}

// ------------------------------------------------------------ the cgroups

func fakeIDs(ids map[string]uint64, root string) cgroupIDOf {
	return func(path string) (uint64, error) {
		rel, _ := filepath.Rel(root, path)
		if rel == "." {
			rel = ""
		}
		id, ok := ids["/"+filepath.ToSlash(rel)]
		if !ok {
			return 0, errors.New("no id for this directory")
		}
		return id, nil
	}
}

func TestMapCgroupIDsNamesEveryDirectoryByItsID(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"system.slice/caddy.service", "system.slice/ssh.socket",
		"user.slice/user-0.slice/session-24.scope", "init.scope"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A file among the directories, like cgroup.procs, is not a cgroup.
	if err := os.WriteFile(filepath.Join(root, "system.slice", "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ids := map[string]uint64{
		"/": 1, "/system.slice": 2, "/system.slice/caddy.service": 3,
		"/system.slice/ssh.socket": 4, "/user.slice": 5, "/user.slice/user-0.slice": 6,
		"/user.slice/user-0.slice/session-24.scope": 7,
		// init.scope has no id in the table, so it is skipped and nothing else is
	}
	byID, err := mapCgroupIDs(root, fakeIDs(ids, root))
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint64]string{1: "/", 2: "/system.slice", 3: "/system.slice/caddy.service",
		4: "/system.slice/ssh.socket", 5: "/user.slice", 6: "/user.slice/user-0.slice",
		7: "/user.slice/user-0.slice/session-24.scope"}
	if len(byID) != len(want) {
		t.Fatalf("got %v, want %v", byID, want)
	}
	for id, path := range want {
		if byID[id] != path {
			t.Errorf("id %d: %q, want %q", id, byID[id], path)
		}
	}
}

func TestMapCgroupIDsStopsAtTheBoundAndSaysSo(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"a", "b", "c", "d"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old := maxCgroupDirs
	maxCgroupDirs = 3
	defer func() { maxCgroupDirs = old }()
	_, err := mapCgroupIDs(root, func(string) (uint64, error) { return 1, nil })
	if !errors.Is(err, errCgroupWalkTruncated) {
		t.Fatalf("err = %v, want errCgroupWalkTruncated", err)
	}
}

func TestMapCgroupIDsWithNoRootIsAnError(t *testing.T) {
	_, err := mapCgroupIDs(filepath.Join(t.TempDir(), "absent"), func(string) (uint64, error) { return 1, nil })
	if err == nil {
		t.Fatal("a missing mount read as an empty tree")
	}
}

func TestUnitOfCgroup(t *testing.T) {
	cases := map[string]string{
		"/system.slice/caddy.service":               "caddy.service",
		"/system.slice/ssh.socket":                  "ssh.socket",
		"/system.slice/docker.service":              "docker.service",
		"/user.slice/user-0.slice/session-24.scope": "session-24.scope",
		"/init.scope":                               "init.scope",
		"/system.slice/system-getty.slice":          "system-getty.slice",
		"/":                                         "",
		"":                                          "",
		"/kubepods/besteffort/pod-1":                "",
		"/system.slice/.service":                    "",
		"/system.slice/caddy.service/cgroup.procs": "",
		"/system.slice/caddy.service/child":        "",
	}
	for path, want := range cases {
		if got := unitOfCgroup(path); got != want {
			t.Errorf("unitOfCgroup(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestJoinCgroupsIsKeyedOnDecimalInodeTextAndBounded(t *testing.T) {
	byInode := map[uint32]uint64{12345: 1, 67890: 2, 4: 3, 5: 4}
	byID := map[uint64]string{
		1: "/system.slice/caddy.service",
		2: "/odd\x1b[31mname.service",
		3: "/" + strings.Repeat("x", hostdoc.MaxCgroupPathLen),
		// id 4 resolves to nothing: the socket keeps no cgroup at all
	}
	got := joinCgroups(byInode, byID)
	if got["12345"] != "/system.slice/caddy.service" {
		t.Errorf("12345: %q", got["12345"])
	}
	if got["67890"] != "/odd?[31mname.service" {
		t.Errorf("control character survived: %q", got["67890"])
	}
	if _, present := got["4"]; present {
		t.Errorf("a path past the cap was kept")
	}
	if _, present := got["5"]; present {
		t.Errorf("an id the tree does not hold was joined to something")
	}
	if len(got) != 2 {
		t.Errorf("got %d entries, want 2: %v", len(got), got)
	}
}

// -------------------------------------------------------------- the join

func fixtureReader(byInode map[string]string, verdict hostdoc.Section) CgroupReader {
	return func() SocketCgroups {
		return SocketCgroups{ByInode: byInode, Sources: map[string]hostdoc.Section{
			"sock_diag": verdict, "cgroup2": verdict}}
	}
}

func TestCollectSocketsCarriesTheUnitFromTheKernelJoinedOnInode(t *testing.T) {
	root := writeProcNet(t, realProcTCP, realProcTCP6, realProcUDP, noFile)
	collected := hostdoc.Section{Status: hostdoc.StatusCollected}
	sec := CollectSockets(root, root, fixtureReader(map[string]string{
		"12345": "/system.slice/ssh.socket",
		"99999": "/system.slice/nothing-listens-here.service",
	}, collected))
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q", sec.Status)
	}
	named := 0
	for _, s := range sec.Listening {
		if s.Port == 22 && s.Family == "v4" {
			if s.Cgroup != "/system.slice/ssh.socket" || s.Unit != "ssh.socket" {
				t.Errorf("port 22: cgroup %q unit %q", s.Cgroup, s.Unit)
			}
			named++
			continue
		}
		if s.Cgroup != "" || s.Unit != "" {
			t.Errorf("%s/%s:%d carries cgroup %q unit %q from nowhere", s.Protocol, s.Family, s.Port, s.Cgroup, s.Unit)
		}
	}
	if named != 1 {
		t.Errorf("named %d sockets, want the one whose inode the kernel placed", named)
	}
	for _, source := range []string{"sock_diag", "cgroup2"} {
		if sec.Sources[source].Status != hostdoc.StatusCollected {
			t.Errorf("source %s = %+v, want collected", source, sec.Sources[source])
		}
	}
	marshalOrFail(t, func(d *hostdoc.Document) { d.Sockets = sec })
}

func TestCollectSocketsWithNoReaderCarriesNoVerdictForIt(t *testing.T) {
	root := writeProcNet(t, realProcTCP, realProcTCP6, realProcUDP, noFile)
	sec := CollectSockets(root, root, nil)
	for _, source := range []string{"sock_diag", "cgroup2"} {
		if _, present := sec.Sources[source]; present {
			t.Errorf("source %s is reported by a build that did not attempt it", source)
		}
	}
	for _, s := range sec.Listening {
		if s.Cgroup != "" || s.Unit != "" {
			t.Errorf("a socket carries a unit with no reader: %+v", s)
		}
	}
}

func TestARefusedReadLeavesTheColumnEmptyAndSaysSo(t *testing.T) {
	root := writeProcNet(t, realProcTCP, realProcTCP6, realProcUDP, noFile)
	refused := hostdoc.Section{Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission}
	sec := CollectSockets(root, root, fixtureReader(nil, refused))
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("a refused unit read must not fail the socket table: status %q", sec.Status)
	}
	if sec.Sources["sock_diag"].Status != hostdoc.StatusPermissionDenied {
		t.Errorf("the refusal is not carried: %+v", sec.Sources["sock_diag"])
	}
	for _, s := range sec.Listening {
		if s.Cgroup != "" || s.Unit != "" {
			t.Errorf("a socket carries a unit from a refused read: %+v", s)
		}
	}
	marshalOrFail(t, func(d *hostdoc.Document) { d.Sockets = sec })
}
