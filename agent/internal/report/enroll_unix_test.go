//go:build unix

package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// These tests are the regression for the first install that failed on
// someone else's server (docs/RECORD.md 4.201). The config file came out
// right, 0640 root:whichports-agent, and the agent still failed every run
// with "stat /etc/whichports/agent.conf: permission denied", because a
// process needs search permission on the directory above a file before it
// can even stat the file, and enroll created that directory with a mode the
// operator's umask had trimmed.
//
// The umask belongs to the whole process, so none of these tests may call
// t.Parallel, and each one puts the old umask back before it returns.

func withUmask(mask int, fn func()) {
	old := syscall.Umask(mask)
	defer syscall.Umask(old)
	fn()
}

// The packaged branch, run without root: the test process's own group
// stands in for whichports-agent, since a process may hand a file it owns to
// any group it belongs to.
func writePackaged(t *testing.T, path string) error {
	t.Helper()
	cfg := Config{Server: "https://app.example.test", Credential: testCredential}
	return writeConfig(path, cfg, os.Getgid(), true)
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}

// The agent runs as whichports-agent and is never the directory's owner, so
// it is judged by the group bits when it is in the directory's group and by
// the other bits when it is not (path_resolution(7)). Both need search. Read
// on the directory is not needed and not added: the agent opens its config
// by name and never lists the directory.
func TestEnrollLeavesTheDirectoryEnterableWhateverTheUmask(t *testing.T) {
	for _, tc := range []struct {
		umask int
		want  os.FileMode
	}{
		{0o022, 0o755}, // the common default, which MkdirAll's 0755 already survives
		{0o027, 0o751}, // a hardened host: 0750, the group could enter and others not
		{0o077, 0o711}, // a strictly hardened host: 0700, nobody but root could enter
	} {
		t.Run(fmt.Sprintf("umask %04o", tc.umask), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "whichports")
			path := filepath.Join(dir, "agent.conf")
			var err error
			withUmask(tc.umask, func() { err = writePackaged(t, path) })
			if err != nil {
				t.Fatal(err)
			}
			if got := modeOf(t, dir).Perm(); got != tc.want {
				t.Errorf("under umask %04o the config directory is %#o, want %#o, "+
					"so the agent's user could not reach the file inside it",
					tc.umask, got, tc.want)
			}
			// The file's own shape is explicit and never came from the umask.
			if got := modeOf(t, path).Perm(); got != 0o640 {
				t.Errorf("config file is %#o, want 0640", got)
			}
			if _, err := Load(path); err != nil {
				t.Errorf("the config enroll just wrote does not load: %v", err)
			}
		})
	}
}

// The directory an earlier enroll left shut is there already, so creating it
// is not enough and running enroll again has to open it. That is the repair
// for a host enrolled before this fix.
func TestEnrollOpensADirectoryAnEarlierEnrollLeftShut(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "whichports")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writePackaged(t, filepath.Join(dir, "agent.conf")); err != nil {
		t.Fatal(err)
	}
	if got := modeOf(t, dir).Perm(); got != 0o711 {
		t.Errorf("re-enrolling left the directory %#o, want 0711", got)
	}
}

// Enroll adds search and takes nothing away. On the control plane's own box
// /etc/whichports also holds the control plane's settings, so a mode someone
// chose there is theirs, and only the two search bits are ours to add.
func TestEnrollOnlyAddsSearchToTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "whichports")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// setgid on a directory is a choice an operator makes so new files take
	// the directory's group. A chmod that only passed the permission bits
	// would clear it.
	if err := os.Chmod(dir, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	if modeOf(t, dir)&os.ModeSetgid == 0 {
		t.Skip("this filesystem would not set setgid on the test directory")
	}
	if err := writePackaged(t, filepath.Join(dir, "agent.conf")); err != nil {
		t.Fatal(err)
	}
	got := modeOf(t, dir)
	if got.Perm() != 0o751 {
		t.Errorf("directory is %#o, want 0751", got.Perm())
	}
	if got&os.ModeSetgid == 0 {
		t.Error("enroll cleared the directory's setgid bit")
	}
}

// chmod follows a symlink, so a link at the config directory would have
// root add search to whatever it points at, and the credential would be
// written through it. postinstall.sh refuses a link at its own two paths for
// the same reason, and so does this.
func TestEnrollRefusesADirectoryThatIsASymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "whichports")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := writePackaged(t, filepath.Join(link, "agent.conf"))
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("enroll through a symlinked directory: got %v, want a refusal naming the symlink", err)
	}
	if got := modeOf(t, target).Perm(); got != 0o700 {
		t.Errorf("the link's target was changed to %#o", got)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a refused enrolment still wrote into the link's target: %v", entries)
	}
}

// Enroll run by hand as an ordinary user, with no whichports-agent group, is
// read back by the same user, so the umask never locks anyone out and the
// directory is left exactly as the operator has it.
func TestEnrollWithoutTheAgentGroupLeavesTheDirectoryAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "whichports")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Server: "https://app.example.test", Credential: testCredential}
	if err := writeConfig(filepath.Join(dir, "agent.conf"), cfg, 0, false); err != nil {
		t.Fatal(err)
	}
	if got := modeOf(t, dir).Perm(); got != 0o700 {
		t.Errorf("a hand-run enrolment changed the directory to %#o", got)
	}
}

// When the directory is shut anyway, by hand or by an agent from before this
// fix, the agent's one line in the journal has to point at the directory,
// because the file it names looks right and that is where anyone would look.
func TestLoadPointsAtTheDirectoryWhenItCannotBeEntered(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root enters any directory, so there is no refusal to read as root")
	}
	dir := filepath.Join(t.TempDir(), "whichports")
	path := filepath.Join(dir, "agent.conf")
	if err := writePackaged(t, path); err != nil {
		t.Fatal(err)
	}
	// No search for the owner, which is what the test process is, so its
	// stat is refused the way the agent user's was.
	if err := os.Chmod(dir, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	_, err := Load(path)
	if err == nil {
		t.Fatal("a config behind a directory nobody may enter loaded")
	}
	for _, want := range []string{"permission denied", "search permission on " + dir, "chmod go+x " + dir} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q:\n%v", want, err)
		}
	}
}
