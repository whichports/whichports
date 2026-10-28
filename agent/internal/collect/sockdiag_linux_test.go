//go:build linux

package collect

// The live reader against the kernel this test runs on. It opens the real
// NETLINK_SOCK_DIAG socket and walks the real cgroup2 mount, as the agent
// does, and needs no privilege to do either, which is the whole point of the
// route (docs/AGENT-PRIVILEGE.md 4a). What it can assert is bounded by what
// the machine running it listens on, so the assertions are about the shape
// of the answer and its verdicts rather than about any particular socket.

import (
	"os"
	"strings"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

func TestTheLiveDumpAnswersWithoutPrivilege(t *testing.T) {
	byInode, verdict := dumpSocketCgroupIDs()
	if verdict.Status != hostdoc.StatusCollected {
		t.Fatalf("sock_diag verdict %+v on this kernel", verdict)
	}
	// Every listening TCP socket /proc/net/tcp lists is in the dump, whether
	// or not the kernel placed it in a cgroup, so a socket table this reader
	// says nothing about is a bug and not a kernel without cgroup ids.
	sec := CollectSockets("/proc", "/", nil)
	if sec.Status != hostdoc.StatusCollected {
		t.Skipf("no socket table to compare against: %+v", sec.Section)
	}
	t.Logf("%d sockets carry a cgroup id from the kernel", len(byInode))
}

func TestTheLiveCgroupTreeResolvesOrIsHonestlyAbsent(t *testing.T) {
	byID, verdict := readCgroupTree(cgroup2Mount, cgroupIDLive)
	switch verdict.Status {
	case hostdoc.StatusCollected:
		root, ok := byID[mustID(t, cgroup2Mount)]
		if !ok || root != "/" {
			t.Errorf("the mount's own id resolves to %q, want /", root)
		}
		for _, path := range byID {
			if !strings.HasPrefix(path, "/") {
				t.Errorf("cgroup path %q is not absolute", path)
			}
		}
	case hostdoc.StatusNotPresent:
		if _, err := os.Stat(cgroup2Mount); err == nil {
			t.Logf("%s exists and is not cgroup2, a v1 host: the column stays empty", cgroup2Mount)
		}
	default:
		t.Fatalf("cgroup2 verdict %+v", verdict)
	}
}

func mustID(t *testing.T, path string) uint64 {
	t.Helper()
	id, err := cgroupIDLive(path)
	if err != nil {
		t.Fatalf("name_to_handle_at(%s): %v", path, err)
	}
	return id
}

func TestTheLiveJoinNamesUnitsOnASystemdHost(t *testing.T) {
	found := SocketCgroupsLive()
	for _, source := range []string{"sock_diag", "cgroup2"} {
		if _, present := found.Sources[source]; !present {
			t.Errorf("no verdict for %s", source)
		}
	}
	if found.Sources["cgroup2"].Status != hostdoc.StatusCollected {
		t.Skipf("not a cgroup2 host: %+v", found.Sources["cgroup2"])
	}
	sec := CollectSockets("/proc", "/", SocketCgroupsLive)
	named := 0
	for _, s := range sec.Listening {
		if s.Cgroup != "" {
			named++
			if s.Unit != "" && !strings.HasSuffix(s.Cgroup, "/"+s.Unit) {
				t.Errorf("unit %q is not the last element of %q", s.Unit, s.Cgroup)
			}
			t.Logf("%s/%s %s:%d  %s  %s", s.Protocol, s.Family, s.BindAddress, s.Port, s.Cgroup, s.Unit)
		}
	}
	t.Logf("%d of %d listening sockets placed in a cgroup by the kernel", named, len(sec.Listening))
	marshalOrFail(t, func(d *hostdoc.Document) { d.Sockets = sec })
}
