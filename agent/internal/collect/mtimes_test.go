package collect

// The mtimes collector's review. Fixture trees are built at runtime because
// git does not preserve modification times, so committed fixtures cannot pin
// them; os.Chtimes gives every file an exact, assertable time.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// writeRuleFile creates a file under root with a fixed mtime.
func writeRuleFile(t *testing.T, root, rel string, mtime int64) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ts := time.Unix(mtime, 0)
	if err := os.Chtimes(path, ts, ts); err != nil {
		t.Fatal(err)
	}
}

func TestRuleFileMtimes(t *testing.T) {
	root := t.TempDir()
	writeRuleFile(t, root, "etc/nftables.conf", 1700000100)
	writeRuleFile(t, root, "etc/ufw/user.rules", 1700000200)
	writeRuleFile(t, root, "etc/firewalld/firewalld.conf", 1700000300)
	// Dynamic zone files are picked up; the .old backup is not.
	writeRuleFile(t, root, "etc/firewalld/zones/public.xml", 1700000400)
	writeRuleFile(t, root, "etc/firewalld/zones/public.xml.old", 1700000500)
	// A file not on the list is ignored even though it sits nearby.
	writeRuleFile(t, root, "etc/ufw/sysctl.conf", 1700000600)

	sec := CollectRuleFileMtimes(root)
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	want := []hostdoc.RuleFileStat{
		{Path: "/etc/firewalld/firewalld.conf", MtimeUnix: 1700000300},
		{Path: "/etc/firewalld/zones/public.xml", MtimeUnix: 1700000400},
		{Path: "/etc/nftables.conf", MtimeUnix: 1700000100},
		{Path: "/etc/ufw/user.rules", MtimeUnix: 1700000200},
	}
	if len(sec.Files) != len(want) {
		t.Fatalf("files = %+v, want %+v", sec.Files, want)
	}
	for i := range want {
		if sec.Files[i] != want[i] {
			t.Errorf("files[%d] = %+v, want %+v", i, sec.Files[i], want[i])
		}
	}
}

func TestRuleFileMtimesEmptyHostIsCollected(t *testing.T) {
	// A host with none of the tools installed measures an empty list. That
	// is an answer, not an error.
	sec := CollectRuleFileMtimes(t.TempDir())
	if sec.Status != hostdoc.StatusCollected || len(sec.Files) != 0 {
		t.Fatalf("empty host: status=%q files=%d, want collected/0", sec.Status, len(sec.Files))
	}
}

func TestRuleFileMtimesDirectorySquatterSkipped(t *testing.T) {
	// A directory sitting on a rule-file path is not a rule file.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/nftables.conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeRuleFile(t, root, "etc/ufw/ufw.conf", 1700000700)
	sec := CollectRuleFileMtimes(root)
	if len(sec.Files) != 1 || sec.Files[0].Path != "/etc/ufw/ufw.conf" {
		t.Fatalf("directory squatter not skipped: %+v", sec.Files)
	}
}

func TestRuleFileMtimesDeterministic(t *testing.T) {
	root := t.TempDir()
	writeRuleFile(t, root, "etc/ufw/user.rules", 1700000200)
	writeRuleFile(t, root, "etc/nftables.conf", 1700000100)
	d1 := hostdoc.New("h", 1)
	d1.RuleFiles = CollectRuleFileMtimes(root)
	d2 := hostdoc.New("h", 1)
	d2.RuleFiles = CollectRuleFileMtimes(root)
	b1, err1 := hostdoc.Marshal(d1)
	b2, err2 := hostdoc.Marshal(d2)
	if err1 != nil || err2 != nil {
		t.Fatalf("marshal errors: %v %v", err1, err2)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("two collections of the same rule files differ")
	}
}

// denyRoot builds a filesystem root holding one readable rule file and one
// that cannot be stat'd, by removing execute on the directory that contains
// it. Running as root defeats the whole point, because root ignores the mode,
// so the caller skips there.
func denyRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores the mode this test relies on")
	}
	root := t.TempDir()
	readable := filepath.Join(root, "etc/ufw")
	if err := os.MkdirAll(readable, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(readable, "user.rules"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(root, "etc/firewalld")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "firewalld.conf"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	return root
}

func TestRuleFileMtimesPartialDenialIsNotCollected(t *testing.T) {
	// The bug this pins: one denied stat used to be invisible whenever any
	// other file read, so the section said collected and the denied file was
	// simply absent from the list, indistinguishable from a file that is not
	// installed. "When did this change" then has a silent hole in it.
	sec := CollectRuleFileMtimes(denyRoot(t))
	if sec.Status != hostdoc.StatusPermissionDenied {
		t.Fatalf("status = %q, want permission_denied when a stat was refused", sec.Status)
	}
	if sec.Cause != hostdoc.CausePermission {
		t.Fatalf("cause = %q, want permission", sec.Cause)
	}
	// The files that did read are still reported. A partial answer is worth
	// more than none, it just may not call itself complete.
	if len(sec.Files) == 0 {
		t.Fatal("the readable rule file was dropped, a denial must not empty the list")
	}
}
