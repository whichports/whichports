//go:build linux

// The live half of the unit-name reader: one NETLINK_SOCK_DIAG socket for the
// four dumps, and name_to_handle_at over the cgroup2 mount. Everything it
// receives goes through the pure functions in sockdiag.go.
//
// What this socket is and is not. It is a client socket: it sends four
// requests and reads the replies, and it is never bound to a listening
// address, so SI-1 holds the same way it holds for the nf_tables netlink
// connection. It is AF_NETLINK, which the packaged unit already permits in
// RestrictAddressFamilies for that connection, so the unit needs no change.
// Nothing is written: a sock_diag dump is a read of socket state and the
// kernel accepts no other verb on this family.
package collect

import (
	"encoding/binary"
	"errors"

	"golang.org/x/sys/unix"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// cgroup2Mount is where systemd mounts the unified hierarchy, which is the
// mount the kernel's cgroup ids resolve against.
const cgroup2Mount = "/sys/fs/cgroup"

// recvBufSize is what one recv can take. The kernel fills a dump datagram up
// to the socket's buffer, and 64 KiB is what ss itself reads with.
const recvBufSize = 64 << 10

// maxDumpBytes bounds one dump. A listening socket is well under a kilobyte
// of reply, so a dump past this is not a socket table and is abandoned.
const maxDumpBytes = 16 << 20

// SocketCgroupsLive reads the live kernel. This is the one function that
// touches netlink or the cgroup mount; everything under it is pure.
func SocketCgroupsLive() SocketCgroups {
	return socketCgroups(cgroup2Mount, cgroupIDLive)
}

func socketCgroups(mount string, idOf cgroupIDOf) SocketCgroups {
	out := SocketCgroups{Sources: map[string]hostdoc.Section{}}
	byInode, diagVerdict := dumpSocketCgroupIDs()
	out.Sources["sock_diag"] = diagVerdict
	byID, treeVerdict := readCgroupTree(mount, idOf)
	out.Sources["cgroup2"] = treeVerdict
	if diagVerdict.Status == hostdoc.StatusCollected && treeVerdict.Status == hostdoc.StatusCollected {
		out.ByInode = joinCgroups(byInode, byID)
	}
	return out
}

// dumpSocketCgroupIDs runs the four dumps and returns inode to cgroup id.
//
// One dump answering ENOENT is a kernel without the diag module for that
// protocol, which is how a host without udp_diag looks (net/ipv4/udp_diag.c
// is CONFIG_INET_UDP_DIAG and can be absent). Those sockets then carry no
// unit and the others still do, so that dump is skipped rather than failing
// the read. Any other error fails the whole source, so a partial read is
// never reported as a complete one.
func dumpSocketCgroupIDs() (map[uint32]uint64, hostdoc.Section) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		switch {
		case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
			return nil, hostdoc.Section{Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission}
		case errors.Is(err, unix.EPROTONOSUPPORT), errors.Is(err, unix.EAFNOSUPPORT):
			// A kernel built without NETLINK_SOCK_DIAG. Measured absence.
			return nil, hostdoc.Section{Status: hostdoc.StatusNotPresent}
		}
		return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseSocketError}
	}
	defer unix.Close(fd)

	byInode := map[uint32]uint64{}
	kernel := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	buf := make([]byte, recvBufSize)
	for _, req := range diagRequests {
		if err := unix.Sendto(fd, encodeDiagRequest(req), 0, kernel); err != nil {
			return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseNetlink}
		}
		total := 0
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseNetlink}
			}
			total += n
			if total > maxDumpBytes {
				return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseNetlink}
			}
			done, perr := parseDiagReply(buf[:n], req.seq, byInode)
			if perr != nil {
				var dumpErr errDiagDump
				if errors.As(perr, &dumpErr) && dumpErr.errno == int32(unix.ENOENT) {
					break
				}
				return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseNetlink}
			}
			if done {
				break
			}
		}
	}
	return byInode, hostdoc.Section{Status: hostdoc.StatusCollected}
}

// readCgroupTree maps every cgroup id under the mount to its path, after
// checking the mount really is cgroup2: a cgroup v1 host has /sys/fs/cgroup
// as a tmpfs of controller mounts, and its directories have no ids the
// kernel's sockets refer to.
func readCgroupTree(mount string, idOf cgroupIDOf) (map[uint64]string, hostdoc.Section) {
	var st unix.Statfs_t
	if err := unix.Statfs(mount, &st); err != nil {
		switch {
		case errors.Is(err, unix.ENOENT):
			return nil, hostdoc.Section{Status: hostdoc.StatusNotPresent}
		case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
			return nil, hostdoc.Section{Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission}
		}
		return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseSourceMissing}
	}
	// Statfs_t.Type is a signed word and the magic is an unsigned constant;
	// compare the low 32 bits, which is all a filesystem magic is.
	if uint32(st.Type) != unix.CGROUP2_SUPER_MAGIC {
		return nil, hostdoc.Section{Status: hostdoc.StatusNotPresent}
	}
	byID, err := mapCgroupIDs(mount, idOf)
	if err != nil {
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return nil, hostdoc.Section{Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission}
		}
		// The walk was cut short at its bound, or the root could not be
		// listed. Either way the map is not the whole tree, and a unit
		// column built from part of a tree would name some sockets and
		// silently not others, so nothing is joined.
		return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseSourceMissing}
	}
	return byID, hostdoc.Section{Status: hostdoc.StatusCollected}
}

// errNotACgroupHandle is a file handle that is not kernfs's 8-byte node id,
// which cannot happen on a cgroup2 mount and is refused rather than decoded.
var errNotACgroupHandle = errors.New("file handle is not a cgroup2 node id")

// cgroupIDLive is name_to_handle_at on one cgroup directory. kernfs encodes
// the handle as the node's u64 id (fs/kernfs/mount.c, kernfs_encode_fh:
// "*(u64 *)fh = kn->id", read at v6.8 on 2026-09-12), and that id is what
// cgroup_id() puts into INET_DIAG_CGROUP_ID for a socket in that cgroup.
// iproute2's lib/cg_map.c reads it the same way. The call is unprivileged:
// name_to_handle_at(2) needs no capability, unlike open_by_handle_at, which
// this never calls.
func cgroupIDLive(path string) (uint64, error) {
	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	if err != nil {
		return 0, err
	}
	b := handle.Bytes()
	if len(b) != 8 {
		return 0, errNotACgroupHandle
	}
	return binary.NativeEndian.Uint64(b), nil
}
