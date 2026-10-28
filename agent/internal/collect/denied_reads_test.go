package collect

// The reads the 2026-08-15 security review flagged and nobody closed.
//
// All three are the same shape: the collector was handed a refusal and passed
// it on as an absence. For this product that is the worst kind of wrong
// answer, because "nothing here" and "I was not allowed to look" lead an
// operator to opposite conclusions.
//
// These tests skip when run as root, because root can read a 0000 directory
// and the denial they depend on never happens.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 directory, so there is no denial to observe")
	}
}

func TestADeniedZoneDirectoryIsNotReportedAsNoZoneFiles(t *testing.T) {
	skipIfRoot(t)
	root := t.TempDir()
	zones := filepath.Join(root, "etc/firewalld/zones")
	if err := os.MkdirAll(zones, 0o755); err != nil {
		t.Fatal(err)
	}
	// A zone file exists, so the honest answer is not "no zone files".
	if err := os.WriteFile(filepath.Join(zones, "public.xml"), []byte("<zone/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(zones, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(zones, 0o755) })

	sec := CollectRuleFileMtimes(root)
	if sec.Status != hostdoc.StatusPermissionDenied {
		t.Fatalf("a denied zone directory must be a denial, got status %q cause %q",
			sec.Status, sec.Cause)
	}
	if sec.Cause != hostdoc.CausePermission {
		t.Fatalf("cause = %q, want %q", sec.Cause, hostdoc.CausePermission)
	}
}

func TestAReadableZoneDirectoryStillCollects(t *testing.T) {
	root := t.TempDir()
	zones := filepath.Join(root, "etc/firewalld/zones")
	if err := os.MkdirAll(zones, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(zones, "public.xml"), []byte("<zone/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	sec := CollectRuleFileMtimes(root)
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	found := false
	for _, f := range sec.Files {
		if strings.HasSuffix(f.Path, "public.xml") {
			found = true
		}
	}
	if !found {
		t.Fatal("the zone file should be listed when the directory is readable")
	}
}

func TestAMissingZoneDirectoryIsNotADenial(t *testing.T) {
	// Most hosts have no firewalld at all. That is a measured answer.
	sec := CollectRuleFileMtimes(t.TempDir())
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected on a host without firewalld", sec.Status)
	}
}

func TestADeniedTailscaleStateDirectoryIsNotReportedAsAbsent(t *testing.T) {
	skipIfRoot(t)
	root := t.TempDir()
	state := filepath.Join(root, tailscaleStateDir)
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	// Deny the parent, so the stat of the state directory itself is refused.
	parent := filepath.Dir(state)
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

	sec := CollectOverlays(root)
	if got := sec.Sources["tailscale"].Status; got != hostdoc.StatusPermissionDenied {
		t.Fatalf("the tailscale source must carry the denial, got %q", got)
	}
}

func TestAnAbsentTailscaleStillReadsAsCollected(t *testing.T) {
	sec := CollectOverlays(t.TempDir())
	if got := sec.Sources["tailscale"].Status; got != hostdoc.StatusCollected {
		t.Fatalf("absence is a measurement, got %q", got)
	}
	if sec.Tailscale.Socket || sec.Tailscale.StateDir {
		t.Fatal("nothing should be reported present on an empty root")
	}
}

func TestADeniedPasswdIsNotReportedAsNoNames(t *testing.T) {
	// The same shape as the zone directory above, one layer down: a passwd
	// the agent may not read means the owner names were refused, not that the
	// file names no uids. The sockets and their uids are untouched by it,
	// because the names are a label on the evidence and never the evidence.
	skipIfRoot(t)
	root := writeProcNet(t, realProcTCP, noFile, noFile, noFile)
	writePasswd(t, root, "root:x:0:0:root:/root:/bin/bash\n")
	if err := os.Chmod(filepath.Join(root, "etc", "passwd"), 0o000); err != nil {
		t.Fatal(err)
	}
	sec := CollectSockets(root, root, nil)
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("sockets stay collected beside a denied passwd, got %q", sec.Status)
	}
	if got := sec.Sources["passwd"]; got.Status != hostdoc.StatusPermissionDenied || got.Cause != hostdoc.CausePermission {
		t.Fatalf("sources[passwd] = %+v, want permission_denied/permission", got)
	}
	for _, s := range sec.Listening {
		if s.OwnerUID == nil || s.OwnerName != "" {
			t.Fatalf("uids survive a denied passwd and names stay empty, got %+v", s)
		}
	}
}

func TestUfwRefusesAFileLargerThanTheCap(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/default")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("A", ufwFileLimit+1)
	path := filepath.Join(dir, "ufw")
	if err := os.WriteFile(path, []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCapped(path); err == nil {
		t.Fatal("a file past the cap must be refused, not truncated")
	}
}

func TestUfwReadsAFileAtTheCap(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ufw.conf")
	if err := os.WriteFile(path, []byte(strings.Repeat("A", ufwFileLimit)), 0o644); err != nil {
		t.Fatal(err)
	}
	content, err := readCapped(path)
	if err != nil {
		t.Fatalf("a file exactly at the cap must be read: %v", err)
	}
	if len(content) != ufwFileLimit {
		t.Fatalf("read %d bytes, want %d", len(content), ufwFileLimit)
	}
}

func TestUfwTruncationIsNeverSilent(t *testing.T) {
	// The point of refusing rather than truncating: half a config parsed
	// confidently is worse than a read that says it failed.
	root := t.TempDir()
	path := filepath.Join(root, "ufw.conf")
	body := "ENABLED=yes\n" + strings.Repeat("#pad\n", ufwFileLimit)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	values, sec := readKeyValueFile(path)
	if sec.Status == hostdoc.StatusCollected {
		t.Fatal("an oversized file must not read as collected")
	}
	if _, ok := values["ENABLED"]; ok {
		t.Fatal("no value should be returned from a refused read")
	}
}
