package packaging

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// Where the package puts its files, held to three facts that broke a real
// install when one of them was not true.
//
// Until 0.1.12 the two programs were in /usr/local/bin. On every RHEL-family
// server the install command stopped at `sudo whichports-agent enroll` with
// "sudo: whichports-agent: command not found", as root too, because sudo
// looks a command up on its own secure_path and that path leaves
// /usr/local/bin out there (docs/RECORD.md 4.220, 4.230). Nothing tested it:
// the clean-box harness called the agent by its full path.

// packageDestinations returns every dst in nfpm.yaml, in file order. The file
// is read as text, a line at a time, because the standard library has no YAML
// reader and the shape here is one quoted path per dst line.
func packageDestinations(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("nfpm.yaml")
	if err != nil {
		t.Fatalf("reading nfpm.yaml: %v", err)
	}
	var dsts []string
	for _, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "dst:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "dst:"))
		value = strings.Trim(value, `"'`)
		if !strings.HasPrefix(value, "/") {
			t.Fatalf("a dst in nfpm.yaml is not an absolute path: %q", line)
		}
		dsts = append(dsts, value)
	}
	if len(dsts) == 0 {
		t.Fatal("nfpm.yaml lists no dst at all, so this reader no longer matches the file")
	}
	return dsts
}

// destinationNamed returns the one dst whose last element is name.
func destinationNamed(t *testing.T, name string) string {
	t.Helper()
	var found []string
	for _, dst := range packageDestinations(t) {
		if path.Base(dst) == name {
			found = append(found, dst)
		}
	}
	if len(found) != 1 {
		t.Fatalf("nfpm.yaml ships %q %d times, want exactly once: %v", name, len(found), found)
	}
	return found[0]
}

// unitValues returns the values of every `key=` line in the shipped service
// unit, comments left out.
func unitValues(t *testing.T, key string) []string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("systemd", "whichports-agent.service"))
	if err != nil {
		t.Fatalf("reading the service unit: %v", err)
	}
	var values []string
	for _, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, key+"=") {
			values = append(values, strings.TrimPrefix(trimmed, key+"="))
		}
	}
	return values
}

// Debian Policy 9.1.2, read 2026-10-02: "packages must not
// place any files in /usr/local, either by putting them in the file system
// archive to be unpacked by dpkg or by manipulating them in their maintainer
// scripts." It also cost a directory: dpkg deleted an empty /usr/local/bin
// when the old layout was purged (docs/RECORD.md 4.173).
func TestThePackageShipsNothingUnderUsrLocal(t *testing.T) {
	for _, dst := range packageDestinations(t) {
		if dst == "/usr/local" || strings.HasPrefix(dst, "/usr/local/") {
			t.Errorf("nfpm.yaml ships %s. /usr/local is the administrator's, "+
				"a package places nothing there (Debian Policy 9.1.2)", dst)
		}
	}
}

// What sudo searches when a command is given by name, read off each system
// rather than assumed. A program the install command or the Remove window
// names after `sudo` has to be in a directory on every one of these.
var measuredSudoPaths = []struct {
	system string
	path   string
}{
	// /etc/sudoers on the almalinux:10 image, 2026-10-02:
	// "Defaults secure_path = /sbin:/bin:/usr/sbin:/usr/bin". Rocky 8.10
	// carries the same line (docs/RECORD.md 4.220).
	{"AlmaLinux 10.2", "/sbin:/bin:/usr/sbin:/usr/bin"},
	// /usr/etc/sudoers on openSUSE Leap 16.0 (docs/RECORD.md 4.230).
	{"openSUSE Leap 16.0", "/usr/sbin:/usr/bin:/sbin:/bin"},
	// /etc/sudoers on the ubuntu:26.04 image, 2026-10-02.
	{"Ubuntu 26.04.1", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"},
}

func TestSudoFindsBothProgramsOnEveryMeasuredSystem(t *testing.T) {
	for _, program := range []string{"whichports-agent", "whichports-uninstall"} {
		dir := path.Dir(destinationNamed(t, program))
		for _, measured := range measuredSudoPaths {
			onPath := false
			for _, entry := range strings.Split(measured.path, ":") {
				if entry == dir {
					onPath = true
				}
			}
			if !onPath {
				t.Errorf("%s is installed in %s, which sudo on %s does not search (%s), "+
					"so `sudo %s` answers \"command not found\" there",
					program, dir, measured.system, measured.path, program)
			}
		}
	}
}

// The unit names the binary twice, and both have to be the path the package
// installs. ExecStart at another path is a unit that cannot start. ExecPaths
// at another path is worse to find: NoExecPaths=/ then makes the kernel
// refuse the agent itself, and the unit fails with a permission error that
// names nothing.
func TestTheUnitRunsTheBinaryThePackageInstalls(t *testing.T) {
	binary := destinationNamed(t, "whichports-agent")

	starts := unitValues(t, "ExecStart")
	if len(starts) != 1 {
		t.Fatalf("the unit has %d ExecStart lines, want exactly one: %v", len(starts), starts)
	}
	fields := strings.Fields(starts[0])
	if len(fields) == 0 || fields[0] != binary {
		t.Errorf("ExecStart runs %q, and the package installs the agent at %s", starts[0], binary)
	}

	allowed := unitValues(t, "ExecPaths")
	if len(allowed) != 1 || allowed[0] != binary {
		t.Errorf("ExecPaths is %v, want exactly [%s]: with NoExecPaths=/ the kernel "+
			"executes nothing else, the agent included", allowed, binary)
	}
	if got := unitValues(t, "NoExecPaths"); len(got) != 1 || got[0] != "/" {
		t.Errorf("NoExecPaths is %v, want [/], or the ExecPaths line above guards nothing", got)
	}
}

// The reader above is only worth its tests if it reads the real file: both
// programs and both units, at the paths this file's other tests reason about.
func TestThePackageShipsItsFourFiles(t *testing.T) {
	want := map[string]bool{
		"/usr/bin/whichports-agent":                        false,
		"/usr/bin/whichports-uninstall":                    false,
		"/usr/lib/systemd/system/whichports-agent.service": false,
		"/usr/lib/systemd/system/whichports-agent.timer":   false,
	}
	for _, dst := range packageDestinations(t) {
		if _, known := want[dst]; !known {
			t.Errorf("nfpm.yaml ships %s, which this test does not know. Add it here "+
				"on purpose, with the reason it is installed where it is", dst)
			continue
		}
		want[dst] = true
	}
	for dst, seen := range want {
		if !seen {
			t.Errorf("nfpm.yaml no longer ships %s", dst)
		}
	}
}
