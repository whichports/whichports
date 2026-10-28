// Package collect holds the host collectors. Each reads one filtering or state
// layer directly, never by executing another program (docs/PRODUCT.md 4e), and
// each is a pure function of the files it reads so it can be tested against
// fixtures with no root and no live host.
//
// This file is the sockets collector: what is listening, and who owns it. It
// reads /proc/net/{tcp,tcp6,udp,udp6}, carries each row's owning uid, names
// that uid from the host's own passwd file, attributes each socket to a
// process by matching socket inodes against /proc/<pid>/fd, and names the
// systemd unit behind each socket from the kernel's own cgroup id, joined on
// the same inode (sockdiag.go). Never by executing ss.
package collect

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// tcpStateListen is the value of the st field for a TCP socket in LISTEN state,
// as /proc/net/tcp reports it (0x0A). Only listening TCP sockets are reported;
// an established connection is not something the internet can newly reach.
const tcpStateListen = 0x0A

// procNetSource names one file to read and how to interpret it. Keeping the four
// as data rather than four code paths means the parser is exercised identically
// for every family and protocol.
type procNetSource struct {
	file     string // relative to the proc net dir, e.g. "tcp6"
	protocol string // "tcp" or "udp"
	family   string // "v4" or "v6"
	isTCP    bool   // whether the LISTEN-state filter applies
}

var procNetSources = []procNetSource{
	{"tcp", "tcp", "v4", true},
	{"tcp6", "tcp", "v6", true},
	{"udp", "udp", "v4", false},
	{"udp6", "udp", "v6", false},
}

// parsedSocket is a listening socket plus the inode used to attribute it to a
// process. The inode does not appear in the host document; it is an internal
// join key only.
type parsedSocket struct {
	sock  hostdoc.ListeningSocket
	inode string
}

// CollectSockets reads the four proc net files under procRoot (normally
// "/proc") and returns the sockets section. fsRoot (normally "/") is where
// etc/passwd is resolved, the same root-prefix convention the file-reading
// collectors use, so tests feed a fixture passwd. It never returns nil: a
// total read failure yields a section whose Status explains why, so the
// document stays honest rather than silently empty.
//
// The function is idempotent and side-effect free: given the same procRoot
// and fsRoot contents it returns the same result, and it writes nothing.
//
// cgroups is the unit-name half, sockdiag.go: the cgroup path of each socket
// by inode, read from the kernel with no capability. nil means this build did
// not attempt it, and then the two sources it would report are absent rather
// than marked, which is what a non-Linux development build says.
func CollectSockets(procRoot, fsRoot string, cgroups CgroupReader) *hostdoc.SocketsSection {
	netDir := filepath.Join(procRoot, "net")

	var all []parsedSocket
	// Every source file gets its own verdict, so a partial failure is visible
	// per file instead of being averaged away (RECORD.md 4.15). tcp parsing
	// while tcp6 is unreadable must never read as "v6 measured and empty".
	sources := make(map[string]hostdoc.Section, len(procNetSources))

	for _, src := range procNetSources {
		content, err := os.ReadFile(filepath.Join(netDir, src.file))
		if err != nil {
			switch {
			case os.IsNotExist(err):
				// A missing family file is a measurement, not an error: with
				// the kernel's v6 stack absent there is no tcp6 file and there
				// are no v6 sockets to report.
				sources[src.file] = hostdoc.Section{Status: hostdoc.StatusNotPresent}
			case os.IsPermission(err):
				sources[src.file] = hostdoc.Section{
					Status: hostdoc.StatusPermissionDenied,
					Cause:  hostdoc.CausePermission,
				}
			default:
				sources[src.file] = hostdoc.Section{
					Status: hostdoc.StatusReadError,
					Cause:  hostdoc.CauseParseFailed,
				}
			}
			continue
		}
		socks, perr := parseProcNet(string(content), src)
		if perr != nil {
			// Read fine, parsed as nothing. A file of garbage must not come
			// out as "collected, nothing listening" - a false all-quiet is the
			// one answer this product must never give.
			sources[src.file] = hostdoc.Section{
				Status: hostdoc.StatusReadError,
				Cause:  hostdoc.CauseParseFailed,
			}
			continue
		}
		sources[src.file] = hostdoc.Section{Status: hostdoc.StatusCollected}
		all = append(all, socks...)
	}

	sec := &hostdoc.SocketsSection{Sources: sources}

	// The section-level status aggregates the per-source verdicts, the shared
	// rule every multi-source collector follows (aggregateSources in ufw.go).
	// For this section, all-absent means the proc path is wrong or unmounted.
	// The aggregate is taken before the passwd verdict is added below, because
	// passwd is a name lookup and not a socket table: a readable passwd next
	// to four absent tables must never make the section read as collected.
	sec.Section = aggregateSources(sources)
	if sec.Status != hostdoc.StatusCollected {
		return sec
	}

	// Attribute processes best-effort. A failure here never fails the section:
	// an unattributed socket is still a real finding, and "we cannot see the
	// owner" is itself information.
	inodeToProc := mapSocketInodes(procRoot)
	for i := range all {
		if p, ok := inodeToProc[all[i].inode]; ok {
			all[i].sock.ProcessName = p.comm
			all[i].sock.PID = p.pid
		}
	}

	// The unit behind each socket, from the kernel's cgroup id, joined on the
	// same inode. Best-effort like the process name: nothing here fails the
	// section, and a socket the kernel did not place keeps an empty Cgroup,
	// which is the honest answer on a kernel before 5.8 or a cgroup v1 host
	// (sockdiag.go). The two reads carry their own verdicts in Sources, so an
	// empty column on a host where the read was refused is distinguishable
	// from one where the kernel named nothing.
	if cgroups != nil {
		found := cgroups()
		for name, verdict := range found.Sources {
			sources[name] = verdict
		}
		for i := range all {
			if path, ok := found.ByInode[all[i].inode]; ok {
				all[i].sock.Cgroup = path
				all[i].sock.Unit = unitOfCgroup(path)
			}
		}
	}

	// Name each owning uid the way the host's own passwd file does. Also
	// best-effort: a uid the file does not name keeps its number and no name,
	// which is the honest answer for a systemd dynamic user or a rootless
	// container owner. The read's own verdict is carried per source, so an
	// unreadable passwd is distinguishable from a passwd that names nothing.
	ownerNames, passwdVerdict := readPasswd(filepath.Join(fsRoot, "etc/passwd"))
	sources["passwd"] = passwdVerdict
	for i := range all {
		if uid := all[i].sock.OwnerUID; uid != nil {
			all[i].sock.OwnerName = ownerNames[*uid]
		}
	}

	listening := make([]hostdoc.ListeningSocket, 0, len(all))
	for _, ps := range all {
		listening = append(listening, ps.sock)
	}
	sortSockets(listening)

	sec.Status = hostdoc.StatusCollected
	sec.Listening = listening
	return sec
}

// parseProcNet parses one /proc/net file. A single malformed row is skipped
// rather than failing the whole file, because one bad line must not lose every
// other socket. But if the file holds data lines and not one of them parses,
// that is an error: the content is not a socket table, and reporting it as
// "collected, empty" would be a false all-quiet.
func parseProcNet(content string, src procNetSource) ([]parsedSocket, error) {
	var out []parsedSocket
	sc := bufio.NewScanner(strings.NewReader(content))
	// Long lines (many fields) are within the default limit, but raise it so a
	// pathological line cannot silently truncate.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	first := true
	dataLines := 0   // non-empty lines that should have been socket rows
	parsedLines := 0 // rows that parsed, whether reported or filtered
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if first {
			// The header row starts with "sl". Skip exactly one header. The
			// kernel writes that header unconditionally (tcp4_seq_show and
			// udp4_format_sock emit it at SEQ_START_TOKEN, checked in the v3.10
			// source and observed on 6.12 and 7.0 kernels, 2026-08-12), so a
			// headerless file should not occur; tolerate one anyway, because
			// defensive parsing must never cost a real socket.
			first = false
			if strings.HasPrefix(line, "sl") {
				continue
			}
		}
		dataLines++
		ps, res := parseProcNetLine(line, src)
		switch res {
		case rowReported:
			parsedLines++
			out = append(out, ps)
		case rowFiltered:
			parsedLines++
		case rowMalformed:
			// Skipped. Counted via dataLines so an all-garbage file still fails.
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if dataLines > 0 && parsedLines == 0 {
		return nil, errNotASocketTable
	}
	return out, nil
}

// errNotASocketTable marks a file whose data lines were all unparseable. The
// text never crosses the wire (SI-8); it is mapped to a typed cause.
var errNotASocketTable = errors.New("no line parsed as a socket row")

// rowResult is what became of one data line. The distinction between filtered
// and malformed matters: a file full of established connections parsed fine and
// is honestly "nothing listening", while a file full of unparseable lines is
// not a socket table and must be reported as a parse failure.
type rowResult int

const (
	rowReported  rowResult = iota // parsed, belongs in the document
	rowFiltered                   // parsed, deliberately not reported
	rowMalformed                  // could not be parsed
)

// parseProcNetLine parses a single data row. Established TCP and connected UDP
// rows are filtered: neither is something the internet can newly reach.
// Skipping a malformed row is the failsafe choice, one unreadable line never
// discards the readable ones, and parseProcNet counts the outcomes.
func parseProcNetLine(line string, src procNetSource) (parsedSocket, rowResult) {
	f := strings.Fields(line)
	// sl local rem st tx:rx tr:when retrnsmt uid timeout inode ...
	if len(f) < 10 {
		return parsedSocket{}, rowMalformed
	}
	local := f[1]
	rem := f[2]
	st, err := strconv.ParseUint(f[3], 16, 16)
	if err != nil {
		return parsedSocket{}, rowMalformed
	}
	inode := f[9]

	// Field 7 is the owning uid, printed by the kernel in decimal (the %5d in
	// get_tcp4_sock's row format, read in the v3.10 net/ipv4/tcp_ipv4.c source
	// on 2026-08-19, and the column every fleet capture in testdata carries).
	// A uid is 32-bit unsigned, so the parse is bounded to that. A row whose
	// uid field does not parse is kept with no uid rather than dropped: the
	// listening socket is the finding, and losing it over one garbled column
	// would be the false all-quiet this file refuses everywhere else.
	var ownerUID *int64
	if uid, err := strconv.ParseUint(f[7], 10, 32); err == nil {
		v := int64(uid)
		ownerUID = &v
	}

	if src.isTCP {
		if st != tcpStateListen {
			return parsedSocket{}, rowFiltered
		}
	} else {
		// UDP has no LISTEN state. A bound server socket is unconnected, so its
		// remote port is zero. A UDP socket with a remote peer is an outbound
		// client, which is not something being served, so filter it.
		remPort, ok := remotePortIsZero(rem)
		if !ok {
			return parsedSocket{}, rowMalformed
		}
		if !remPort {
			return parsedSocket{}, rowFiltered
		}
	}

	addr, port, ok := parseLocalAddr(local, src.family)
	if !ok {
		return parsedSocket{}, rowMalformed
	}

	return parsedSocket{
		sock: hostdoc.ListeningSocket{
			Protocol:    src.protocol,
			Family:      src.family,
			BindAddress: addr,
			Port:        port,
			OwnerUID:    ownerUID,
		},
		inode: inode,
	}, rowReported
}

// remotePortIsZero reports, for a "HEXADDR:HEXPORT" remote field, whether the
// port is zero. The second return is false if the field is malformed.
func remotePortIsZero(rem string) (isZero bool, ok bool) {
	i := strings.LastIndex(rem, ":")
	if i < 0 {
		return false, false
	}
	p, err := strconv.ParseUint(rem[i+1:], 16, 32)
	if err != nil {
		return false, false
	}
	return p == 0, true
}

// parseLocalAddr splits "HEXADDR:HEXPORT" and decodes both halves. The address
// encoding differs by family and is the fiddly part: /proc writes each 32-bit
// word of the address in the host's byte order, which is little-endian on the
// platforms this runs on.
func parseLocalAddr(s, family string) (addr string, port int, ok bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, false
	}
	hexAddr := s[:i]
	hexPort := s[i+1:]

	p, err := strconv.ParseUint(hexPort, 16, 32)
	if err != nil || p > 65535 {
		return "", 0, false
	}

	switch family {
	case "v4":
		a, ok := decodeV4(hexAddr)
		if !ok {
			return "", 0, false
		}
		return a, int(p), true
	case "v6":
		a, ok := decodeV6(hexAddr)
		if !ok {
			return "", 0, false
		}
		return a, int(p), true
	default:
		return "", 0, false
	}
}

// decodeV4 turns the 8-hex-char little-endian word from /proc into dotted quad.
// "0100007F" is the 32-bit value 0x7F000001, which is 127.0.0.1.
func decodeV4(h string) (string, bool) {
	if len(h) != 8 {
		return "", false
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", false
	}
	v := binary.LittleEndian.Uint32(b)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip.String(), true
}

// decodeV6 turns the 32-hex-char address from /proc into a v6 string. The 16
// bytes are stored as four 32-bit words, each in little-endian order, so each
// group of 8 hex chars is byte-reversed before being placed.
func decodeV6(h string) (string, bool) {
	if len(h) != 32 {
		return "", false
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return "", false
	}
	ip := make(net.IP, 16)
	for word := 0; word < 4; word++ {
		v := binary.LittleEndian.Uint32(raw[word*4 : word*4+4])
		binary.BigEndian.PutUint32(ip[word*4:word*4+4], v)
	}
	// A v4-mapped address (::ffff:a.b.c.d) is kept in that explicit form.
	// net.IP.String() would render it as a bare "a.b.c.d", and then a v6-family
	// socket would carry an address that reads as v4, which conflates the two
	// families the document keeps strictly apart (docs/PRODUCT.md 4b).
	if v4 := ip.To4(); v4 != nil {
		return "::ffff:" + v4.String(), true
	}
	return ip.String(), true
}

// procInfo is a process that owns a socket.
type procInfo struct {
	pid  int
	comm string
}

// initPID is process 1. The kernel gives it to init unconditionally, so this
// is a kernel fact rather than a systemd one and holds on any Linux.
const initPID = 1

// betterHolder decides which of two processes holding the same socket is the
// one worth naming. Returns true when candidate should replace current.
//
// **More than one process can hold one listening socket**, which the first
// version of this file did not allow for, and the two ways it happens are both
// ordinary:
//
//   - **Socket activation.** systemd opens the listening socket and passes the
//     fd to the service, so init and the service both hold it. Measured on the
//     production box 2026-08-16, where ssh.socket and ssh.service are both
//     active and ss reports
//     `users:(("sshd",pid=1078,fd=3),("systemd",pid=1,fd=259))`.
//   - **A master with forked workers**, which nginx and Caddy do. Every worker
//     inherits the listening fd.
//
// So the rule is two lines and both of them are about being useful to a reader
// rather than about being clever:
//
//  1. **Init is the answer of last resort.** Naming systemd for a socket-
//     activated service tells the operator nothing, and it is the wrong answer
//     on the one port everybody looks at first. Init is still named when it is
//     genuinely the only holder, because then it is the true answer.
//  2. **Otherwise the lowest pid**, which for a master and its workers is the
//     master, because the workers were forked from it. It is also the only
//     choice here that does not depend on the order /proc happens to be walked
//     in, and that ordering was the original bug: os.ReadDir sorts lexically,
//     so "1" beat "1078" and "1001" beat "900".
//
// What this deliberately does not do is report every holder. That would change
// the host document schema (PRODUCT.md 4e), which is a decision rather than a
// fix, and it is on the board.
func betterHolder(current, candidate procInfo) bool {
	if current.pid == initPID && candidate.pid != initPID {
		return true
	}
	if candidate.pid == initPID && current.pid != initPID {
		return false
	}
	return candidate.pid < current.pid
}

// mapSocketInodes builds inode -> owning process by walking /proc/<pid>/fd and
// reading each symlink, which points at "socket:[<inode>]" for socket fds. It is
// best-effort: any pid whose fd directory cannot be read (permission, or the
// process exited mid-walk) is skipped, never fatal.
//
// Where several processes hold one inode, betterHolder above decides which one
// the document names.
func mapSocketInodes(procRoot string) map[string]procInfo {
	result := map[string]procInfo{}

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return result
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a pid directory
		}
		fdDir := filepath.Join(procRoot, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process gone, or not ours to read
		}
		comm := readComm(filepath.Join(procRoot, e.Name(), "comm"))
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := socketInode(target)
			if !ok {
				continue
			}
			candidate := procInfo{pid: pid, comm: comm}
			if seen, ok := result[inode]; !ok || betterHolder(seen, candidate) {
				result[inode] = candidate
			}
		}
	}
	return result
}

// socketInode extracts <inode> from a "socket:[<inode>]" symlink target.
func socketInode(linkTarget string) (string, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(linkTarget, prefix) || !strings.HasSuffix(linkTarget, "]") {
		return "", false
	}
	return linkTarget[len(prefix) : len(linkTarget)-1], true
}

// readComm reads a process comm, trimming the trailing newline. An unreadable
// comm yields an empty name, which the document represents honestly as an
// attributed pid with no name rather than a failure.
//
// The name is sanitized because a process chooses it itself (prctl
// PR_SET_NAME takes arbitrary bytes), and stdout mode prints the document on
// an operator's terminal. Control characters are how a name becomes a
// terminal escape sequence, so they are replaced, not passed through. The
// signal that survives, a process with a strange name, is the honest part.
func readComm(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return sanitizeName(strings.TrimRight(string(b), "\n"))
}

// readPasswd reads a passwd file and maps each uid to the name the file gives
// it. It exists so the owning uid on a socket can be shown as the user the
// host itself knows, which matters most under a non-root agent, where process
// names are unreadable and the uid is the attribution that remains
// (docs/RECORD.md 4.64). The file is read directly rather than through
// os/user so the path honours the collector's root prefix, tests feed a
// fixture, and the parse stays a pure function of the file content.
//
// The verdict follows the package posture: a missing file is not_present, a
// denied one is the denial, and a file whose data lines all fail to parse is
// a parse failure, because garbage must never read as an empty success. What
// it deliberately does not do is consult anything beyond this one file: a
// host resolving users from LDAP or NSS modules keeps bare uids, honestly,
// rather than this agent growing lookups it cannot do as a static binary.
func readPasswd(path string) (map[int64]string, hostdoc.Section) {
	content, err := readCapped(path)
	if err != nil {
		return nil, fileVerdict(err)
	}
	return parsePasswd(string(content))
}

// parsePasswd parses passwd content: one "name:password:uid:..." entry per
// line, colon separated, per passwd(5). Only the name and the uid are read.
// A malformed line is skipped, never fatal, the same failsafe the socket
// parser uses. When two lines carry the same uid the first wins, a choice
// made here for determinism rather than to mirror any particular libc.
func parsePasswd(content string) (map[int64]string, hostdoc.Section) {
	out := map[int64]string{}
	dataLines, parsedLines := 0, 0
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		dataLines++
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		uid, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			continue
		}
		parsedLines++
		// A passwd entry is host-provided text and stdout mode prints on a
		// terminal, so the name takes the same sanitisation every host name
		// does. An empty name or one past the login-name cap labels nothing:
		// the uid stays in the document and the label is honestly absent,
		// which the fail-closed marshaller also enforces (hostdoc.MaxOwnerNameLen).
		name := sanitizeName(f[0])
		if name == "" || len(name) > hostdoc.MaxOwnerNameLen {
			continue
		}
		if _, seen := out[int64(uid)]; !seen {
			out[int64(uid)] = name
		}
	}
	if err := sc.Err(); err != nil {
		return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	}
	if dataLines > 0 && parsedLines == 0 {
		return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	}
	return out, hostdoc.Section{Status: hostdoc.StatusCollected}
}

// SanitizeHostText exposes this package's control-character policy for the
// one host-provided string built outside it, the hostname in cmd/agent. Same
// rule, same reason: stdout mode prints on a terminal (RECORD.md 4.14).
func SanitizeHostText(s string) string {
	return sanitizeName(s)
}

// sanitizeName replaces every control character with '?': C0 (below 0x20),
// DEL, and the C1 range 0x80-0x9f, which JSON does not escape and which can
// reach a terminal encoded as valid UTF-8. Bytes that are not valid UTF-8
// decode as utf8.RuneError and come out as the replacement character, which
// is harmless on both the wire and a terminal.
func sanitizeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return '?'
		}
		return r
	}, s)
}

// sortSockets orders the list deterministically so two runs over the same host
// state produce byte-identical documents. Ordering is by protocol, then family,
// then port, then bind address, then pid. The pid tie-break exists for
// SO_REUSEPORT, where several processes listen on an identical address and
// port and the sort key would otherwise not be total.
func sortSockets(s []hostdoc.ListeningSocket) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].Protocol != s[j].Protocol {
			return s[i].Protocol < s[j].Protocol
		}
		if s[i].Family != s[j].Family {
			return s[i].Family < s[j].Family
		}
		if s[i].Port != s[j].Port {
			return s[i].Port < s[j].Port
		}
		if s[i].BindAddress != s[j].BindAddress {
			return s[i].BindAddress < s[j].BindAddress
		}
		return s[i].PID < s[j].PID
	})
}
