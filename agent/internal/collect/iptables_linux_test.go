//go:build linux

package collect

// The live legacy read against the kernel this test runs on. A collection
// must leave the kernel's legacy tables exactly as it found them: the agent
// is read only (SI-3), and asking the kernel about a table it does not hold
// makes it create that table, and load the table's module where it is one
// (xt_request_find_table_lock in net/netfilter/x_tables.c).
//
// It means most where the kernel holds none of the five tables in this test's
// network namespace, the usual state of a fresh container, which is where it
// was written to fail on the old read.

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// tableList reads one family's list of the tables the kernel holds. ok is
// false when this process may not read it.
func tableList(t *testing.T, path string) (content string, exists, ok bool) {
	t.Helper()
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		return string(b), true, true
	case errors.Is(err, fs.ErrNotExist):
		return "", false, true
	case errors.Is(err, fs.ErrPermission):
		return "", true, false
	}
	t.Fatalf("reading %s: %v", path, err)
	return "", false, false
}

func TestALegacyCollectionLeavesTheKernelTablesAsTheyWere(t *testing.T) {
	for _, fam := range []struct {
		name    string
		path    string
		collect func() *hostdoc.IptablesSection
	}{
		{"iptables", "/proc/net/ip_tables_names", CollectIptablesLive},
		{"ip6tables", "/proc/net/ip6_tables_names", CollectIp6tablesLive},
	} {
		t.Run(fam.name, func(t *testing.T) {
			before, existedBefore, readable := tableList(t, fam.path)
			sec := fam.collect()
			after, existsAfter, _ := tableList(t, fam.path)

			if existedBefore != existsAfter {
				t.Fatalf("%s existed %v before the collection and %v after", fam.path, existedBefore, existsAfter)
			}
			if !readable {
				// The list is 0440 root's. A process that cannot read it
				// must not have asked the kernel about any table, so no
				// table can read as collected.
				for table, src := range sec.Sources {
					if src.Status == hostdoc.StatusCollected {
						t.Errorf("table %s collected by a process that cannot read %s", table, fam.path)
					}
				}
				return
			}
			if before != after {
				t.Fatalf("the kernel's %s tables changed with a collection:\nbefore %q\nafter  %q", fam.name, before, after)
			}
			listed := map[string]bool{}
			for _, line := range splitLines(before) {
				listed[line] = true
			}
			for _, table := range legacyTables {
				got := sec.Sources[table].Status
				switch {
				case !listed[table] && got != hostdoc.StatusNotPresent:
					t.Errorf("table %s is not in the kernel's list and reads %s", table, got)
				case listed[table] && got != hostdoc.StatusCollected && got != hostdoc.StatusPermissionDenied:
					t.Errorf("table %s is in the kernel's list and reads %s", table, got)
				}
			}
		})
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}
