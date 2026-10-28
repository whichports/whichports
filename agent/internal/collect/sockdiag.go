// This file is the unit-name half of the sockets collector: which systemd
// unit owns each listening socket, read from the kernel over sock_diag
// netlink and the cgroup2 filesystem, and joined to the socket table on the
// inode both carry. Everything here is a pure function of bytes and paths so
// it is tested on any platform; sockdiag_linux.go is the one file that talks
// to a live kernel.
//
// Why this exists. Naming the process behind a port by reading /proc/<pid>/fd
// needs CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE together, and that pair reads
// any file and any process's memory on the host (docs/AGENT-PRIVILEGE.md
// sections 3 and 5). The kernel puts the cgroup id of every socket into every
// inet_diag reply with no capability check at all: inet_sk_diag_fill in
// net/ipv4/inet_diag.c writes INET_DIAG_CGROUP_ID outside every privilege
// conditional in the function (read at v7.0, 2026-09-08). A cgroup id resolves
// to a directory on the cgroup2 mount, and on a systemd host that directory
// is the unit. So "caddy.service" is available to a process holding nothing,
// which is what the owner chose on 2026-09-12 (docs/RECORD.md 4.169).
//
// Where it stops, stated rather than discovered: INET_DIAG_CGROUP_ID first
// appears in Linux 5.8 (include/uapi/linux/inet_diag.h at v5.7 lacks it, v5.8
// has it), so RHEL 8 and CentOS 7 send no id and the column stays empty. A
// cgroup v1 host has no cgroup2 mount to resolve against and the column stays
// empty. A Docker published port belongs to docker.service, and the container
// itself is named by the containers collector. Empty is the honest answer in
// every one of those cases, and nothing here falls back to the capability
// route.
package collect

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// The netlink and inet_diag constants this file needs, each from the kernel's
// own uapi headers, read at v6.8 on 2026-09-12. They are spelled out here
// rather than taken from golang.org/x/sys so the parser compiles and is
// tested on every platform; the live reader in sockdiag_linux.go uses the
// x/sys spellings for the socket itself.
const (
	// include/uapi/linux/sock_diag.h
	sockDiagByFamily = 20
	// include/uapi/linux/netlink.h
	nlmsgHdrLen = 16
	nlmsgError  = 2
	nlmsgDone   = 3
	nlmFRequest = 0x1
	nlmFMulti   = 0x2
	nlmFDump    = 0x300
	nlaHdrLen   = 4
	nlaAlignTo  = 4
	nlaTypeMask = 0x3fff // the two flag bits above it are not the type
	// include/uapi/linux/inet_diag.h: struct inet_diag_req_v2 is 56 bytes,
	// struct inet_diag_msg is 72, with idiag_inode the last u32 in it.
	inetDiagReqLen   = 56
	inetDiagMsgLen   = 72
	inetDiagInodeOff = 68
	inetDiagCgroupID = 21 // INET_DIAG_CGROUP_ID, counted in the extensions enum
	// include/uapi/linux/tcp.h: TCP_LISTEN is 10 in enum tcp_states, and
	// idiag_states is a bitmask over that enum.
	tcpListen = 10
	// A UDP socket has no LISTEN state; its unconnected state is TCP_CLOSE
	// (7), so every state is asked for and the join on inode does the
	// filtering, since only sockets already in the table are looked up.
	allStates = 0xffffffff
	// Address families and protocols, include/uapi/linux/socket.h and in.h.
	afInet     = 2
	afInet6    = 10
	ipprotoTCP = 6
	ipprotoUDP = 17
)

// nativeEndian is the byte order of netlink, which is the host's own. The
// agent ships for amd64 only (agent/Makefile, packaging/nfpm.yaml) and Go's
// binary.NativeEndian says which that is without this file guessing.
var nativeEndian = binary.NativeEndian

// diagRequest is one dump request: every socket of one family and one
// protocol in the given states.
type diagRequest struct {
	family, protocol uint8
	states           uint32
	seq              uint32
}

// diagRequests are the four dumps a collection makes, one per socket table
// the /proc/net reader already reads, so the two sides ask about the same
// sockets. The sequence numbers are how a reply is matched to its request.
var diagRequests = []diagRequest{
	{afInet, ipprotoTCP, 1 << tcpListen, 1},
	{afInet6, ipprotoTCP, 1 << tcpListen, 2},
	{afInet, ipprotoUDP, allStates, 3},
	{afInet6, ipprotoUDP, allStates, 4},
}

// encodeDiagRequest builds the netlink message for one dump: an nlmsghdr
// followed by struct inet_diag_req_v2 with an empty socket id, which is how a
// dump asks for every socket rather than one.
func encodeDiagRequest(r diagRequest) []byte {
	b := make([]byte, nlmsgHdrLen+inetDiagReqLen)
	nativeEndian.PutUint32(b[0:4], uint32(len(b)))
	nativeEndian.PutUint16(b[4:6], sockDiagByFamily)
	nativeEndian.PutUint16(b[6:8], nlmFRequest|nlmFDump)
	nativeEndian.PutUint32(b[8:12], r.seq)
	nativeEndian.PutUint32(b[12:16], 0) // pid: the kernel fills in the sender
	b[nlmsgHdrLen+0] = r.family
	b[nlmsgHdrLen+1] = r.protocol
	b[nlmsgHdrLen+2] = 0 // idiag_ext: no extension asked for, the cgroup id needs none
	b[nlmsgHdrLen+3] = 0 // pad
	nativeEndian.PutUint32(b[nlmsgHdrLen+4:nlmsgHdrLen+8], r.states)
	// The 48-byte struct inet_diag_sockid stays zero: no port, no address, no
	// interface and no cookie, so the dump is unfiltered.
	return b
}

// errDiagDump is what a dump returns when the kernel answered with an error
// message rather than sockets. The errno is kept for the verdict and never
// enters the document (SI-8).
type errDiagDump struct{ errno int32 }

func (e errDiagDump) Error() string { return "sock_diag dump answered with an error" }

// errDiagMalformed is a reply that does not parse as netlink. It is treated
// like an error from the kernel: nothing from that dump is used.
var errDiagMalformed = errors.New("sock_diag reply is not well-formed netlink")

// parseDiagReply reads one datagram's worth of netlink messages and adds
// every socket's inode and cgroup id to byInode. It returns done=true once a
// NLMSG_DONE has been seen, which ends the dump. Messages for another
// sequence number are skipped rather than misfiled, and a message the kernel
// marks as an error ends the dump with errDiagDump.
//
// A message that does not fit its own length, or a header past the buffer,
// is errDiagMalformed. The kernel does not send those, but the parser must
// not read past a slice on any input, which is what the fuzz target holds.
func parseDiagReply(b []byte, seq uint32, byInode map[uint32]uint64) (done bool, err error) {
	for len(b) > 0 {
		if len(b) < nlmsgHdrLen {
			return false, errDiagMalformed
		}
		msgLen := int(nativeEndian.Uint32(b[0:4]))
		msgType := nativeEndian.Uint16(b[4:6])
		flags := nativeEndian.Uint16(b[6:8])
		msgSeq := nativeEndian.Uint32(b[8:12])
		if msgLen < nlmsgHdrLen || msgLen > len(b) {
			return false, errDiagMalformed
		}
		payload := b[nlmsgHdrLen:msgLen]
		// The next message starts at the aligned length, and the last one
		// may be unpadded.
		next := nlmsgAlign(msgLen)
		if next > len(b) {
			next = len(b)
		}
		b = b[next:]

		if msgSeq != seq {
			continue
		}
		switch msgType {
		case nlmsgDone:
			return true, nil
		case nlmsgError:
			// struct nlmsgerr starts with a negative errno; zero is an
			// acknowledgement and not an error, which a dump never sends.
			if len(payload) < 4 {
				return false, errDiagMalformed
			}
			errno := int32(nativeEndian.Uint32(payload[0:4]))
			if errno == 0 {
				continue
			}
			return false, errDiagDump{errno: -errno}
		case sockDiagByFamily:
			if inode, id, ok := parseDiagMessage(payload); ok {
				byInode[inode] = id
			}
		}
		if flags&nlmFMulti == 0 {
			// A reply that is not part of a multi-part dump is complete on
			// its own. Dumps set the flag; a lone message without it is the
			// end, or the kernel would have told us to keep reading.
			return true, nil
		}
	}
	return false, nil
}

// nlmsgAlign rounds a length up to the netlink alignment, NLMSG_ALIGNTO, 4.
func nlmsgAlign(n int) int { return (n + nlaAlignTo - 1) &^ (nlaAlignTo - 1) }

// parseDiagMessage reads one struct inet_diag_msg and the attributes after it,
// and returns the socket's inode and cgroup id. ok is false when the message
// is too short to be one or carries no INET_DIAG_CGROUP_ID, which is what a
// kernel older than 5.8 sends: absent, not zero.
func parseDiagMessage(payload []byte) (inode uint32, cgroupID uint64, ok bool) {
	if len(payload) < inetDiagMsgLen {
		return 0, 0, false
	}
	inode = nativeEndian.Uint32(payload[inetDiagInodeOff : inetDiagInodeOff+4])
	attrs := payload[inetDiagMsgLen:]
	for len(attrs) >= nlaHdrLen {
		attrLen := int(nativeEndian.Uint16(attrs[0:2]))
		attrType := nativeEndian.Uint16(attrs[2:4]) & nlaTypeMask
		if attrLen < nlaHdrLen || attrLen > len(attrs) {
			// A truncated attribute ends the walk for this message; what was
			// read before it stands and what comes after is not trusted.
			return 0, 0, false
		}
		value := attrs[nlaHdrLen:attrLen]
		if attrType == inetDiagCgroupID && len(value) == 8 {
			return inode, nativeEndian.Uint64(value), true
		}
		next := nlmsgAlign(attrLen)
		if next > len(attrs) {
			break
		}
		attrs = attrs[next:]
	}
	return 0, 0, false
}

// cgroupIDOf answers the cgroup id of one directory on the cgroup2 mount. On
// Linux it is name_to_handle_at, whose 8-byte handle on kernfs is the node's
// id, which is what cgroup_id() returns for the socket (fs/kernfs/mount.c,
// kernfs_encode_fh, and iproute2's lib/cg_map.c, which does the same). The
// tests hand in a table.
type cgroupIDOf func(path string) (uint64, error)

// maxCgroupDirs bounds the walk. A big host has thousands of cgroups and a
// pathological one could have millions; the walk stops here and the verdict
// says the read is not complete rather than spending the collection on it.
var maxCgroupDirs = 65536

// errCgroupWalkTruncated is a cgroup tree with more directories than the
// walk will visit.
var errCgroupWalkTruncated = errors.New("cgroup2 tree has more directories than the walk visits")

// mapCgroupIDs walks the cgroup2 mount at root and returns id to path, where
// the path is the cgroup's own name relative to the mount, "/" for the root
// cgroup. A directory whose id cannot be read is skipped: one unreadable
// cgroup must not blank every other unit.
func mapCgroupIDs(root string, idOf cgroupIDOf) (map[uint64]string, error) {
	byID := map[uint64]string{}
	visited := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// The root itself unreadable is the caller's verdict; a child
			// unreadable is skipped.
			if path == root {
				return walkErr
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		visited++
		if visited > maxCgroupDirs {
			return errCgroupWalkTruncated
		}
		id, err := idOf(path)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		name := "/"
		if rel != "." {
			name = "/" + filepath.ToSlash(rel)
		}
		// The first path seen for an id wins. WalkDir is lexical, so this is
		// deterministic, and two directories with one id do not happen on a
		// real kernfs.
		if _, seen := byID[id]; !seen {
			byID[id] = name
		}
		return nil
	})
	return byID, err
}

// unitSuffixes are the systemd unit types a cgroup directory can be named
// after. systemd names a unit's cgroup after the unit (systemd.resource-
// control(7), "each unit is assigned a cgroup"), so the last element of the
// path is the unit when it ends in one of these.
var unitSuffixes = []string{".service", ".socket", ".scope", ".slice"}

// unitOfCgroup is the systemd unit a cgroup path ends in, or "".
func unitOfCgroup(path string) string {
	last := path[strings.LastIndex(path, "/")+1:]
	for _, suffix := range unitSuffixes {
		if strings.HasSuffix(last, suffix) && len(last) > len(suffix) {
			return last
		}
	}
	return ""
}

// SocketCgroups is what the live reader hands the sockets collector: the
// cgroup path of every socket by inode, and one verdict per source it read.
// The map is nil when nothing could be joined, and the verdicts say why.
type SocketCgroups struct {
	ByInode map[string]string
	Sources map[string]hostdoc.Section
}

// CgroupReader produces the join input. It is a function so the live kernel
// reader, a fixture and nil (not attempted) all fit the one call in
// CollectSockets.
type CgroupReader func() SocketCgroups

// joinCgroups turns the two kernel maps into inode to cgroup path, bounded
// and sanitised the way every other host string is, so a cgroup directory
// with a control character in its name reaches neither the wire nor a
// terminal unchanged.
func joinCgroups(byInode map[uint32]uint64, byID map[uint64]string) map[string]string {
	out := map[string]string{}
	for inode, id := range byInode {
		path, ok := byID[id]
		if !ok {
			continue
		}
		path = sanitizeName(path)
		if len(path) > hostdoc.MaxCgroupPathLen {
			continue
		}
		out[strconvUint(inode)] = path
	}
	return out
}

// strconvUint is strconv.FormatUint for a u32 inode, spelled out so the join
// key is visibly the same decimal text the /proc/net parser produces.
func strconvUint(n uint32) string {
	if n == 0 {
		return "0"
	}
	var digits [10]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}

// sortedInodes exists for deterministic test output and nothing else.
func sortedInodes(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
