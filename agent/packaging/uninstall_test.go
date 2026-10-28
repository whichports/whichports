package packaging

// uninstall.sh run for real, against a pretend machine.
//
// Until 2026-10-03 the only test of the uninstaller parsed it and read its
// text, because the script deletes things as root and must never run on the
// machine a test runs on. So nothing held what it does, and three faults were
// found on real distributions instead (docs/RECORD.md 4.335):
//
//   - on a host with neither apt-get, dnf nor yum it removed no package and
//     said "Removed". The same whenever a removal failed
//   - it asked `hostname` for the machine's name, which a minimal image lacks
//   - it left our signing key in rpm's own keyring
//
// The harness below makes running it safe. Every path the script writes to is
// rewritten into a temporary directory, the same way runPostinstallOnTree
// does it, and PATH holds one directory of stubs and nothing else, so no real
// package manager can be reached even where the test runs as root.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The paths uninstall.sh names in its own variables, each rewritten into the
// pretend machine's root.
var uninstallPaths = []string{
	"/etc/whichports",
	"/var/lib/whichports",
	"/etc/apt/sources.list.d/whichports.list",
	"/etc/apt/apt.conf.d/51whichports",
	"/usr/share/keyrings/whichports.gpg",
	"/etc/yum.repos.d/whichports.repo",
	"/etc/pki/rpm-gpg/RPM-GPG-KEY-whichports",
	"/etc/systemd/system/whichports-agent.service.d",
}

const (
	ourKeyShort   = "gpg-pubkey-6e2c982d-6a7d7e2a"
	ourKeyLong    = "gpg-pubkey-3eedc9c6e4940a815d42ce43680a90826e2c982d-6a7d7e2a"
	someoneElses  = "gpg-pubkey-a15b79cc-63d04c2c"
	agentPackage  = "whichports-agent"
	removedSaying = "Removed. This host no longer reports."
)

// uninstallHost is one pretend machine.
type uninstallHost struct {
	t    *testing.T
	root string // stands for /
	bin  string // the only directory on PATH
	db   string // one file per package a package database holds
	flag string // a file here switches one stub's behaviour
	log  string // every stub call, one line each: the command and its arguments
}

// newUninstallHost builds a machine that has the given commands and nothing
// else. Every machine also has id, uname, rm and rmdir, which the script needs
// wherever it runs. `hostname` is never among them, on purpose.
func newUninstallHost(t *testing.T, commands ...string) *uninstallHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell scripts are not exercised on Windows")
	}
	dir := t.TempDir()
	h := &uninstallHost{
		t:    t,
		root: filepath.Join(dir, "root"),
		bin:  filepath.Join(dir, "bin"),
		db:   filepath.Join(dir, "db"),
		flag: filepath.Join(dir, "flag"),
		log:  filepath.Join(dir, "calls.log"),
	}
	for _, d := range []string{h.root, h.bin, h.db, h.flag} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// rm and rmdir are the real ones, reached through a link, because whether
	// the files went is what several tests assert.
	for _, tool := range []string{"rm", "rmdir"} {
		real, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("this machine has no %s: %v", tool, err)
		}
		if err := os.Symlink(real, filepath.Join(h.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	h.stub("id", `echo 0`)
	h.stub("uname", `echo testbox`)
	for _, name := range commands {
		body, known := uninstallStubs[name]
		if !known {
			t.Fatalf("no stub is written for %s", name)
		}
		h.stub(name, body)
	}
	return h
}

// What each stub does once its call is logged. DB and FLAG are set by the
// header every stub gets. They use shell builtins and rm, since nothing else
// is on PATH.
var uninstallStubs = map[string]string{
	"systemctl": `exit 0`,
	"setfacl":   `exit 0`,
	"gpasswd":   `exit 0`,

	// apt-get purge takes the package out of dpkg's database, unless a lock
	// is held, which is the failure a person meets.
	"apt-get": `
if [ -e "$FLAG/apt-get-fails" ]; then
  echo "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242 (unattended-upgr)"
  exit 100
fi
rm -f "$DB/dpkg-whichports-agent"
exit 0`,

	// dpkg-query prints the status and exits 0 for a package it holds, and
	// exits 1 with nothing on stdout for one it does not (measured on Debian
	// 13, 2026-10-03).
	"dpkg-query": `
if [ -e "$DB/dpkg-whichports-agent" ]; then
  printf 'install ok installed'
  exit 0
fi
echo "dpkg-query: no packages found matching whichports-agent" >&2
exit 1`,

	"dnf": `
if [ -e "$FLAG/dnf-fails" ]; then
  echo "Error: the rpm database is locked by another process"
  exit 1
fi
rm -f "$DB/whichports-agent"
exit 0`,

	"yum": `
if [ -e "$FLAG/yum-fails" ]; then
  echo "Error: the rpm database is locked by another process"
  exit 1
fi
rm -f "$DB/whichports-agent"
exit 0`,

	// rpm -q answers on stdout either way and exits 1 for a package it does
	// not hold. Asked for gpg-pubkey it lists every key, one name a line.
	"rpm": `
if [ "$1" = -q ] && [ "$2" = gpg-pubkey ]; then
  found=no
  for f in "$DB"/gpg-pubkey-*; do
    [ -e "$f" ] || continue
    echo "${f##*/}"
    found=yes
  done
  [ "$found" = yes ] && exit 0
  echo "package gpg-pubkey is not installed"
  exit 1
fi
if [ "$1" = -q ]; then
  if [ -e "$DB/$2" ]; then
    if [ "$2" = whichports-agent ]; then echo "whichports-agent-0.1.12-1.x86_64"; else echo "$2"; fi
    exit 0
  fi
  echo "package $2 is not installed"
  exit 1
fi
if [ "$1" = -e ]; then
  if [ -e "$FLAG/rpm-e-fails" ]; then
    echo "error: can not create transaction lock on /usr/lib/sysimage/rpm/.rpm.lock"
    exit 1
  fi
  if [ -e "$DB/$2" ]; then rm -f "$DB/$2"; exit 0; fi
  echo "error: package $2 is not installed"
  exit 1
fi
exit 2`,

	// rpmkeys --delete as rpm 4.19 and later have it, and as rpm 4.14 and
	// 4.16 answer it (measured in containers, 2026-10-03).
	"rpmkeys": `
if [ "$1" = --delete ] && [ -e "$FLAG/rpmkeys-has-delete" ]; then
  for f in "$DB"/gpg-pubkey-"$2"-*; do
    [ -e "$f" ] || { echo "error: package gpg-pubkey-$2 is not installed"; exit 1; }
    rm -f "$f"
  done
  exit 0
fi
echo "rpmkeys: --delete: unknown option" >&2
exit 1`,
}

func (h *uninstallHost) stub(name, body string) {
	h.t.Helper()
	text := "#!/bin/sh\n" +
		"DB=" + shellQuote(h.db) + "\n" +
		"FLAG=" + shellQuote(h.flag) + "\n" +
		"printf '%s\\n' \"" + name + " $*\" >> " + shellQuote(h.log) + "\n" +
		body + "\n"
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte(text), 0o755); err != nil {
		h.t.Fatalf("writing the %s stub: %v", name, err)
	}
}

// holds puts packages into the pretend package database. A deb is recorded
// as dpkg-<name>, an rpm and a key by the name rpm gives it.
func (h *uninstallHost) holds(names ...string) {
	h.t.Helper()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(h.db, name), nil, 0o644); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *uninstallHost) stillHolds(name string) bool {
	_, err := os.Stat(filepath.Join(h.db, name))
	return err == nil
}

func (h *uninstallHost) set(flag string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.flag, flag), nil, 0o644); err != nil {
		h.t.Fatal(err)
	}
}

// installed writes every file the installer leaves, so a run has something
// to remove.
func (h *uninstallHost) installed() {
	h.t.Helper()
	for _, path := range uninstallPaths {
		at := filepath.Join(h.root, path)
		isDir := path == "/etc/whichports" || path == "/var/lib/whichports" ||
			strings.HasSuffix(path, ".service.d")
		if isDir {
			if err := os.MkdirAll(at, 0o755); err != nil {
				h.t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
			h.t.Fatal(err)
		}
		if err := os.WriteFile(at, []byte("x"), 0o644); err != nil {
			h.t.Fatal(err)
		}
	}
	for _, file := range []string{"/etc/whichports/agent.conf", "/var/lib/whichports/host.json"} {
		if err := os.WriteFile(filepath.Join(h.root, file), []byte("x"), 0o600); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *uninstallHost) leftOnDisk() []string {
	var left []string
	for _, path := range uninstallPaths {
		if _, err := os.Lstat(filepath.Join(h.root, path)); err == nil {
			left = append(left, path)
		}
	}
	return left
}

func (h *uninstallHost) calls() []string {
	h.t.Helper()
	data, err := os.ReadFile(h.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func (h *uninstallHost) called(line string) bool {
	for _, call := range h.calls() {
		if call == line {
			return true
		}
	}
	return false
}

var shellAssignment = regexp.MustCompile(`(?m)^[A-Z_]+="(/[^"]*)"$`)

// run rewrites the script onto this machine and runs it. It hands back what
// the person would read, stdout and stderr together, and the exit status.
func (h *uninstallHost) run(stdin string, args ...string) (string, int) {
	h.t.Helper()
	src, err := os.ReadFile("uninstall.sh")
	if err != nil {
		h.t.Fatalf("reading uninstall.sh: %v", err)
	}
	script := string(src)
	for _, path := range uninstallPaths {
		from := `="` + path + `"`
		if !strings.Contains(script, from) {
			h.t.Fatalf("uninstall.sh no longer sets a variable to %s, so this "+
				"harness must be updated to match", path)
		}
		script = strings.ReplaceAll(script, from, `="`+filepath.Join(h.root, path)+`"`)
	}
	// The guard that makes this safe to run: every path the script holds in a
	// variable is inside the pretend root now. A path added to the script and
	// not to uninstallPaths stops the test here, before anything is removed.
	for _, match := range shellAssignment.FindAllStringSubmatch(script, -1) {
		if !strings.HasPrefix(match[1], h.root+"/") {
			h.t.Fatalf("uninstall.sh holds %s, which this harness does not "+
				"rewrite. Add it to uninstallPaths.", match[1])
		}
	}
	rewritten := filepath.Join(filepath.Dir(h.bin), "uninstall.sh")
	if err := os.WriteFile(rewritten, []byte(script), 0o755); err != nil {
		h.t.Fatal(err)
	}

	shell, err := exec.LookPath("sh")
	if err != nil {
		h.t.Fatalf("this machine has no sh: %v", err)
	}
	cmd := exec.Command(shell, append([]string{rewritten}, args...)...)
	// The stub directory and nothing else. Not this machine's PATH with the
	// stubs in front: a package manager the scenario leaves out has to be
	// absent, and a real one must be out of reach.
	cmd.Env = []string{"PATH=" + h.bin}
	cmd.Stdin = strings.NewReader(stdin)
	out, runErr := cmd.CombinedOutput()
	code := 0
	if runErr != nil {
		var exit *exec.ExitError
		if !errors.As(runErr, &exit) {
			h.t.Fatalf("uninstall.sh did not run: %v\n%s", runErr, out)
		}
		code = exit.ExitCode()
	}
	return string(out), code
}

// ---------------------------------------------------------------- the package

// The four ways a host removes the package, each as it goes right and as it
// goes wrong. The last one is openSUSE: rpm, and neither dnf nor yum.
func TestUninstallSaysRemovedOnlyWhenThePackageIsGone(t *testing.T) {
	cases := []struct {
		name     string
		commands []string
		held     string // the name the pretend database holds the package under
		wantCall string // the removal the script has to ask for
		failFlag string // what makes that removal fail
		leftLine string // what the script says is still installed
		said     string // the package manager's own words, which must be shown
	}{
		{"apt", []string{"apt-get", "dpkg-query"}, "dpkg-whichports-agent",
			"apt-get purge -y whichports-agent", "apt-get-fails",
			"dpkg: whichports-agent, install ok installed", "E: Could not get lock"},
		{"dnf", []string{"dnf", "yum", "rpm", "rpmkeys"}, agentPackage,
			"dnf remove -y whichports-agent", "dnf-fails",
			"rpm: whichports-agent-0.1.12-1.x86_64", "the rpm database is locked"},
		{"yum alone", []string{"yum", "rpm"}, agentPackage,
			"yum remove -y whichports-agent", "yum-fails",
			"rpm: whichports-agent-0.1.12-1.x86_64", "the rpm database is locked"},
		{"rpm alone", []string{"rpm", "rpmkeys"}, agentPackage,
			"rpm -e whichports-agent", "rpm-e-fails",
			"rpm: whichports-agent-0.1.12-1.x86_64", "can not create transaction lock"},
	}
	for _, tc := range cases {
		t.Run(tc.name+", removed", func(t *testing.T) {
			h := newUninstallHost(t, append(tc.commands, "systemctl")...)
			h.installed()
			h.holds(tc.held)

			out, code := h.run("", "--yes")

			if code != 0 {
				t.Fatalf("exit %d, want 0\n%s", code, out)
			}
			if !h.called(tc.wantCall) {
				t.Errorf("the script never ran %q. It ran:\n%s", tc.wantCall,
					strings.Join(h.calls(), "\n"))
			}
			if h.stillHolds(tc.held) {
				t.Error("the package is still in the database")
			}
			if !strings.Contains(out, removedSaying) {
				t.Errorf("the script does not say it removed everything:\n%s", out)
			}
			if strings.Contains(out, "Not finished") {
				t.Errorf("the script says it is not finished:\n%s", out)
			}
			if left := h.leftOnDisk(); len(left) != 0 {
				t.Errorf("left on disk: %v", left)
			}
		})
		t.Run(tc.name+", the removal fails", func(t *testing.T) {
			h := newUninstallHost(t, append(tc.commands, "systemctl")...)
			h.installed()
			h.holds(tc.held)
			h.set(tc.failFlag)

			out, code := h.run("", "--yes")

			if code == 0 {
				t.Errorf("exit 0 with the package still installed\n%s", out)
			}
			if strings.Contains(out, "Removed.") {
				t.Errorf("the script says Removed with the package still installed:\n%s", out)
			}
			for _, want := range []string{
				"Not finished. The whichports-agent package is still installed:",
				tc.leftLine,
				"The package manager said:",
				tc.said,
			} {
				if !strings.Contains(out, want) {
					t.Errorf("the output lacks %q:\n%s", want, out)
				}
			}
			// What it tells every operator at the end is still told.
			if !strings.Contains(out, "the host is not revoked") {
				t.Errorf("the revocation note is gone from a failed run:\n%s", out)
			}
		})
	}
}

// Fedora has both dnf and yum. One of them removes the package, not both.
func TestUninstallAsksOnePackageManager(t *testing.T) {
	h := newUninstallHost(t, "dnf", "yum", "rpm", "rpmkeys", "systemctl")
	h.installed()
	h.holds(agentPackage)

	h.run("", "--yes")

	for _, call := range h.calls() {
		if strings.HasPrefix(call, "yum ") || call == "rpm -e whichports-agent" {
			t.Errorf("with dnf on the host the script also ran %q", call)
		}
	}
}

// The package manager's exit status is not the answer. A removal that says
// it failed and did remove the package is a removal.
func TestUninstallBelievesTheDatabaseAndNotTheExitStatus(t *testing.T) {
	h := newUninstallHost(t, "rpm", "systemctl")
	h.installed()
	h.holds(agentPackage)
	h.stub("rpm", strings.Replace(uninstallStubs["rpm"],
		`if [ -e "$DB/$2" ]; then rm -f "$DB/$2"; exit 0; fi`,
		`if [ -e "$DB/$2" ]; then rm -f "$DB/$2"; echo "warning: a scriptlet failed"; exit 1; fi`, 1))

	out, code := h.run("", "--yes")

	if code != 0 || !strings.Contains(out, removedSaying) {
		t.Errorf("exit %d, and the package is gone from the database:\n%s", code, out)
	}
}

// ------------------------------------------------------------- the machine's name

// No machine in these tests has a hostname command, as the openSUSE Leap 16.0
// and Fedora 44 images do not. The script used to print "hostname: command
// not found" in the middle of its first line there.
func TestUninstallNamesTheMachineWithoutHostname(t *testing.T) {
	h := newUninstallHost(t, "apt-get", "dpkg-query", "systemctl")
	h.installed()

	out, _ := h.run("", "--yes")

	if !strings.HasPrefix(out, "This will remove from testbox:\n") {
		t.Errorf("the first line does not name the machine:\n%s", out)
	}
	if strings.Contains(out, "not found") {
		t.Errorf("the script ran a command this machine does not have:\n%s", out)
	}
}

// --------------------------------------------------------- the key in rpm's keyring

func TestUninstallTakesOurKeyOutOfRpmsKeyring(t *testing.T) {
	// Names that look like ours and are not: one character more in front,
	// one more behind.
	decoys := []string{someoneElses, "gpg-pubkey-06e2c982d-11111111", "gpg-pubkey-6e2c982d0-22222222"}
	cases := []struct {
		name      string
		key       string
		rpmkeys   bool // the host has an rpmkeys command
		hasDelete bool // and it knows --delete
		wantCall  string
	}{
		{"rpm 4.19 and 4.20", ourKeyShort, true, true, "rpmkeys --delete 6e2c982d"},
		{"rpm 6", ourKeyLong, true, true,
			"rpmkeys --delete 3eedc9c6e4940a815d42ce43680a90826e2c982d"},
		{"rpm 4.14 and 4.16, no --delete", ourKeyShort, true, false, "rpm -e " + ourKeyShort},
		{"no rpmkeys at all", ourKeyShort, false, false, "rpm -e " + ourKeyShort},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			commands := []string{"dnf", "rpm", "systemctl"}
			if tc.rpmkeys {
				commands = append(commands, "rpmkeys")
			}
			h := newUninstallHost(t, commands...)
			h.installed()
			h.holds(agentPackage, tc.key)
			h.holds(decoys...)
			if tc.hasDelete {
				h.set("rpmkeys-has-delete")
			}

			out, code := h.run("", "--yes")

			if code != 0 || !strings.Contains(out, removedSaying) {
				t.Errorf("exit %d:\n%s", code, out)
			}
			if h.stillHolds(tc.key) {
				t.Errorf("our key is still in the keyring. The script ran:\n%s",
					strings.Join(h.calls(), "\n"))
			}
			if !h.called(tc.wantCall) {
				t.Errorf("the script never ran %q. It ran:\n%s", tc.wantCall,
					strings.Join(h.calls(), "\n"))
			}
			// Every other key is left alone, and is never even named to a
			// command that deletes.
			for _, decoy := range decoys {
				if !h.stillHolds(decoy) {
					t.Errorf("%s was removed, and it is not ours", decoy)
				}
				version := strings.TrimPrefix(decoy, "gpg-pubkey-")
				version = version[:strings.LastIndex(version, "-")]
				for _, call := range h.calls() {
					if call == "rpm -e "+decoy || call == "rpmkeys --delete "+version {
						t.Errorf("the script ran %q on a key that is not ours", call)
					}
				}
			}
		})
	}
}

func TestUninstallSaysSoWhenOurKeyCouldNotBeRemoved(t *testing.T) {
	h := newUninstallHost(t, "dnf", "rpm", "rpmkeys", "systemctl")
	h.installed()
	h.holds(agentPackage, ourKeyShort)
	h.set("rpm-e-fails") // and rpmkeys has no --delete here

	out, code := h.run("", "--yes")

	if code == 0 {
		t.Errorf("exit 0 with our key still in the keyring\n%s", out)
	}
	if strings.Contains(out, "Removed.") {
		t.Errorf("the script says Removed with our key still there:\n%s", out)
	}
	for _, want := range []string{
		"Not finished. The whichports signing key is still in rpm's keyring:",
		"  " + ourKeyShort,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	// dnf did remove the package, and the script does not say otherwise.
	if strings.Contains(out, "package is still installed") {
		t.Errorf("the script blames the package, which is gone:\n%s", out)
	}
}

// A host with no key of ours, and a Debian host with no rpm at all, are left
// alone: nothing is deleted from a keyring and nothing is reported.
func TestUninstallLeavesAKeyringWithoutOurKeyAlone(t *testing.T) {
	t.Run("rpm host, other keys only", func(t *testing.T) {
		h := newUninstallHost(t, "dnf", "rpm", "rpmkeys", "systemctl")
		h.installed()
		h.holds(agentPackage, someoneElses)
		h.set("rpmkeys-has-delete")

		out, code := h.run("", "--yes")

		if code != 0 || !strings.Contains(out, removedSaying) {
			t.Errorf("exit %d:\n%s", code, out)
		}
		for _, call := range h.calls() {
			if strings.HasPrefix(call, "rpmkeys ") || strings.HasPrefix(call, "rpm -e gpg-pubkey") {
				t.Errorf("the script ran %q with no key of ours on the host", call)
			}
		}
		if !h.stillHolds(someoneElses) {
			t.Error("another vendor's key was removed")
		}
	})
	t.Run("rpm host, an empty keyring", func(t *testing.T) {
		h := newUninstallHost(t, "dnf", "rpm", "rpmkeys", "systemctl")
		h.installed()
		h.holds(agentPackage)

		out, code := h.run("", "--yes")

		if code != 0 || !strings.Contains(out, removedSaying) {
			t.Errorf("exit %d:\n%s", code, out)
		}
	})
	t.Run("debian host", func(t *testing.T) {
		h := newUninstallHost(t, "apt-get", "dpkg-query", "systemctl")
		h.installed()
		h.holds("dpkg-whichports-agent")

		h.run("", "--yes")

		for _, call := range h.calls() {
			if strings.HasPrefix(call, "rpm") {
				t.Errorf("the script ran %q on a host without rpm", call)
			}
		}
	})
}

// The key's two names are written out in uninstall.sh. They have to be the
// fingerprint install.sh pins, or a rotated key would be left behind on
// every host with nothing failing.
func TestUninstallKnowsTheKeyTheInstallerPins(t *testing.T) {
	read := func(file, variable string) string {
		t.Helper()
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		found := regexp.MustCompile(`(?m)^` + variable + `="([^"]+)"$`).FindStringSubmatch(string(data))
		if found == nil {
			t.Fatalf("%s does not set %s", file, variable)
		}
		return found[1]
	}
	pinned := strings.ToLower(read("install.sh", "KEY_FPR"))
	if len(pinned) != 40 {
		t.Fatalf("install.sh pins %q, which is not a 40 character fingerprint", pinned)
	}
	if long := read("uninstall.sh", "KEY_ID_LONG"); long != pinned {
		t.Errorf("uninstall.sh looks for %s and install.sh pins %s", long, pinned)
	}
	if short := read("uninstall.sh", "KEY_ID_SHORT"); short != pinned[32:] {
		t.Errorf("uninstall.sh looks for %s and the pinned key ends in %s", short, pinned[32:])
	}
	if !strings.Contains(ourKeyLong, pinned) || !strings.Contains(ourKeyShort, "-"+pinned[32:]+"-") {
		t.Error("the key names these tests use are not the pinned key's")
	}
}

// ------------------------------------------------------------ before it starts

func TestUninstallChangesNothingWithoutAYes(t *testing.T) {
	// The last one is no answer at all, the input closed: the script stops
	// at the question without a word, and that is a no as well.
	for _, answer := range []string{"n\n", "\n", "maybe\n", ""} {
		h := newUninstallHost(t, "apt-get", "dpkg-query", "systemctl")
		h.installed()
		h.holds("dpkg-whichports-agent")

		out, code := h.run(answer)

		if code != 1 {
			t.Errorf("answer %q: exit %d\n%s", answer, code, out)
		}
		if answer != "" && !strings.Contains(out, "Nothing was changed.") {
			t.Errorf("answer %q: the script does not say nothing was changed\n%s", answer, out)
		}
		if strings.Contains(out, "Removed") {
			t.Errorf("answer %q: the script says it removed something\n%s", answer, out)
		}
		if len(h.leftOnDisk()) != len(uninstallPaths) || !h.stillHolds("dpkg-whichports-agent") {
			t.Errorf("answer %q: something was removed", answer)
		}
		if calls := h.calls(); len(calls) != 2 || calls[0] != "id -u" || calls[1] != "uname -n" {
			t.Errorf("answer %q: the script ran more than its two questions: %v", answer, calls)
		}
	}
}

func TestUninstallAnsweredYesGoesAhead(t *testing.T) {
	h := newUninstallHost(t, "apt-get", "dpkg-query", "systemctl")
	h.installed()
	h.holds("dpkg-whichports-agent")

	out, code := h.run("y\n")

	if code != 0 || !strings.Contains(out, removedSaying) {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestUninstallRefusesWithoutRoot(t *testing.T) {
	h := newUninstallHost(t, "apt-get", "dpkg-query", "systemctl")
	h.installed()
	h.holds("dpkg-whichports-agent")
	h.stub("id", `echo 1000`)

	out, code := h.run("", "--yes")

	if code != 1 || !strings.Contains(out, "run this as root") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	if len(h.leftOnDisk()) != len(uninstallPaths) || !h.stillHolds("dpkg-whichports-agent") {
		t.Error("something was removed without root")
	}
}

// ------------------------------------------------------ where to revoke it

// The second big test, 2026-10-25, case B12: on a server enrolled to a
// self-hosted instance the last line sent the person to our own dashboard,
// where the server is not, and the credential stayed live on their
// instance. The script removes /etc/whichports, which held the address,
// before that line, so it reads the address first.

func enrolledTo(t *testing.T, h *uninstallHost, conf string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.root, "/etc/whichports/agent.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUninstallNamesTheDashboardTheHostReportedTo(t *testing.T) {
	h := newUninstallHost(t, "apt-get", "dpkg-query", "systemctl")
	h.installed()
	enrolledTo(t, h, "# written by whichports-agent enroll\n"+
		"server https://instance.example.org\ncredential whk_x\n")

	out, _ := h.run("", "--yes")

	if !strings.HasSuffix(out, "anywhere else, at\nhttps://instance.example.org\n") {
		t.Errorf("the last line is not the instance the host reported to:\n%s", out)
	}
	if strings.Contains(out, "app.whichports.com") {
		t.Errorf("names our dashboard for a host enrolled elsewhere:\n%s", out)
	}
}

func TestUninstallNamesNoAddressWhenTheEnrolmentSaysNone(t *testing.T) {
	for name, conf := range map[string]string{
		"no server line": "credential whk_x\n",
		"not a web address": "server instance.example.org\n",
		"a character no address has": "server https://instance.example.org/\x1b[2J\n",
	} {
		t.Run(name, func(t *testing.T) {
			h := newUninstallHost(t, "apt-get", "dpkg-query", "systemctl")
			h.installed()
			enrolledTo(t, h, conf)

			out, _ := h.run("", "--yes")

			if !strings.HasSuffix(out, "so the credential cannot be used from anywhere else.\n") {
				t.Errorf("the sentence does not end where the address would be:\n%q", out)
			}
			if strings.Contains(out, "app.whichports.com") || strings.Contains(out, "\x1b") {
				t.Errorf("printed an address the enrolment did not give:\n%q", out)
			}
		})
	}
}
