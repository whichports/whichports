// Package packaging holds tests for the install and remove scriptlets that
// nfpm embeds in the .deb and .rpm. The scripts are shell, so the tests run
// them under a fake `systemctl` and assert on what they tried to do.
//
// These exist because a scriptlet with no test shipped a fleet-wide silent
// failure: the pre-remove disabled the timer on every upgrade, so an ordinary
// `apt upgrade` or `dnf upgrade` stopped the host reporting (docs/RECORD.md,
// 2026-08-15). A scriptlet is exactly the kind of code nobody runs by hand and
// nobody reviews closely, which is where this project keeps finding its quiet
// failures, so it gets the same treatment as the collectors: reproduce the
// failure, then guard it.
package packaging

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runScriptlet runs one scriptlet with the given argument, on a PATH where the
// only `systemctl` is a stub that appends its arguments to a log file. It
// returns everything that stub was asked to do, one invocation per line.
//
// The argument is what the package manager passes the scriptlet, and the two
// managers say the same things differently:
//
//	deb  passes "upgrade" while upgrading and "remove" on a real removal.
//	rpm  passes the count of versions that will remain: "1" on upgrade,
//	     "0" on the final erase.
func runScriptlet(t *testing.T, script, arg string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell scriptlets are not exercised on Windows")
	}

	dir := t.TempDir()
	log := filepath.Join(dir, "systemctl.log")

	// A stub systemctl. It records the call and exits 0, so the scriptlet
	// runs to completion exactly as it would on a host, without touching this
	// machine's real units.
	stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + shellQuote(log) + "\nexit 0\n"
	stubPath := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(stubPath, []byte(stub), 0o755); err != nil {
		t.Fatalf("writing systemctl stub: %v", err)
	}

	scriptPath, err := filepath.Abs(filepath.Join("scripts", script))
	if err != nil {
		t.Fatalf("resolving script path: %v", err)
	}

	cmd := exec.Command("sh", scriptPath, arg)
	// Only the stub dir is on PATH, so `command -v systemctl` finds the stub
	// and nothing else. /bin is added so `sh` itself and its builtins resolve.
	cmd.Env = append(os.Environ(), "PATH="+dir+":/bin:/usr/bin")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scriptlet %s %q failed: %v\n%s", script, arg, err, out)
	}

	data, err := os.ReadFile(log)
	if os.IsNotExist(err) {
		return "" // systemctl was never called
	}
	if err != nil {
		t.Fatalf("reading systemctl log: %v", err)
	}
	return string(data)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runPostinstall runs postinstall.sh with every host-mutating command replaced
// by a stub that logs what it was asked to do. Same philosophy as the
// systemctl stub above: the scriptlet's decisions are what get asserted, and
// the real effect on a real host is asserted by ops/cleanbox in containers.
//
// userExists steers the getent stub for both lookups, group and passwd, which
// is the difference between a first install and every install after it.
func runPostinstall(t *testing.T, userExists bool) map[string]string {
	logs, _ := runPostinstallWithTimer(t, userExists, true)
	return logs
}

// runPostinstallWithTimer is the same harness with the two facts the closing
// message reads made steerable, and with stdout handed back, because what the
// operator is told is the thing being asserted.
//
// timerEnabled steers `systemctl is-enabled`, which is how the script learns
// whether the operator has already turned the timer on. Every other systemctl
// call still logs and succeeds.
func runPostinstallWithTimer(t *testing.T, userExists, timerEnabled bool) (map[string]string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell scriptlets are not exercised on Windows")
	}

	dir := t.TempDir()
	stubbed := []string{"groupadd", "useradd", "mkdir", "chown", "chmod", "systemctl"}
	for _, name := range stubbed {
		log := filepath.Join(dir, name+".log")
		stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + shellQuote(log) + "\nexit 0\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(stub), 0o755); err != nil {
			t.Fatalf("writing %s stub: %v", name, err)
		}
	}
	// systemctl answers is-enabled with an exit code and logs everything else,
	// so daemon-reload still records the way the other stubs do.
	isEnabledExit := "1"
	if timerEnabled {
		isEnabledExit = "0"
	}
	systemctlStub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " +
		shellQuote(filepath.Join(dir, "systemctl.log")) +
		"\nif [ \"$1\" = is-enabled ]; then exit " + isEnabledExit + "; fi\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(systemctlStub), 0o755); err != nil {
		t.Fatalf("writing systemctl stub: %v", err)
	}
	// getent answers the exists question rather than logging: 0 is found,
	// 2 is getent's own code for "not found in the database".
	getentExit := "2"
	if userExists {
		getentExit = "0"
	}
	if err := os.WriteFile(filepath.Join(dir, "getent"),
		[]byte("#!/bin/sh\nexit "+getentExit+"\n"), 0o755); err != nil {
		t.Fatalf("writing getent stub: %v", err)
	}

	scriptPath, err := filepath.Abs(filepath.Join("scripts", "postinstall.sh"))
	if err != nil {
		t.Fatalf("resolving script path: %v", err)
	}
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(), "PATH="+dir+":/bin:/usr/bin")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("postinstall.sh failed: %v\n%s", err, out)
	}

	logs := map[string]string{}
	for _, name := range stubbed {
		data, err := os.ReadFile(filepath.Join(dir, name+".log"))
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("reading %s log: %v", name, err)
		}
		logs[name] = string(data)
	}
	return logs, string(out)
}

// runPostinstallOnTree runs postinstall.sh against a real directory tree, with
// its two hardcoded paths rewritten to point inside one. It returns the chown
// log, the combined output, and the run error.
//
// The stub harness above asserts what the script asked for. This one exists
// for a fault where asking is the bug: chown and chmod follow a symlink, so
// what the script asked for and what the filesystem then did are two different
// facts. mkdir and chmod run for real here so the dereference behaviour is the
// kernel's rather than a stub's. chown stays a logging stub because handing a
// file to another user needs root, and getent answers "exists" so the
// user-creation branch, which also needs root, never runs.
func runPostinstallOnTree(t *testing.T, stateDir, confFile string) (string, string, error) {
	t.Helper()
	// A /usr/local that already has its bin, which is every machine the
	// script's last step must leave alone, and no staff-group file.
	usrLocal := filepath.Join(t.TempDir(), "usr-local")
	if err := os.MkdirAll(filepath.Join(usrLocal, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	return runPostinstallOnTreeWithUsrLocal(t, stateDir, confFile, usrLocal,
		filepath.Join(usrLocal, "no-staff-group-file"))
}

// runPostinstallOnTreeWithUsrLocal is the same harness with the two paths of
// the script's /usr/local/bin step rewritten as well: /usr/local itself, and
// the file whose presence says /usr/local belongs to root:staff (Debian
// Policy 9.1.2). Without the rewrite that step would read, and could change,
// the /usr/local of the machine the test runs on.
func runPostinstallOnTreeWithUsrLocal(t *testing.T, stateDir, confFile, usrLocal, staffFile string) (string, string, error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell scriptlets are not exercised on Windows")
	}

	dir := t.TempDir()
	chownLogPath := filepath.Join(dir, "chown.log")
	stubs := map[string]string{
		"chown":     "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + shellQuote(chownLogPath) + "\nexit 0\n",
		"getent":    "#!/bin/sh\nexit 0\n",
		"systemctl": "#!/bin/sh\nexit 0\n",
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatalf("writing %s stub: %v", name, err)
		}
	}

	src, err := os.ReadFile(filepath.Join("scripts", "postinstall.sh"))
	if err != nil {
		t.Fatalf("reading postinstall.sh: %v", err)
	}
	script := string(src)
	for _, sub := range []struct{ from, to string }{
		// /usr/local first, so no path substituted in below can be rewritten
		// a second time on a machine whose temp directory sits under it.
		{"/usr/local", usrLocal},
		{"/etc/staff-group-for-usr-local", staffFile},
		{"/var/lib/whichports", stateDir},
		{"/etc/whichports/agent.conf", confFile},
	} {
		if !strings.Contains(script, sub.from) {
			t.Fatalf("postinstall.sh no longer mentions %s, so this rewrite "+
				"harness must be updated to match", sub.from)
		}
		script = strings.ReplaceAll(script, sub.from, sub.to)
	}
	scriptPath := filepath.Join(dir, "postinstall.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("writing the rewritten scriptlet: %v", err)
	}

	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(), "PATH="+dir+":/bin:/usr/bin")
	out, runErr := cmd.CombinedOutput()

	data, err := os.ReadFile(chownLogPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("reading chown log: %v", err)
	}
	return string(data), string(out), runErr
}

// A first install has to create the agent's own user, as a system account with
// no login shell, because the unit says User=whichports-agent and a unit whose
// user does not exist fails at start with an error nobody connects to the
// package.
func TestPostinstallCreatesTheAgentUser(t *testing.T) {
	logs := runPostinstall(t, false)
	if !strings.Contains(logs["groupadd"], "--system whichports-agent") {
		t.Errorf("groupadd was not asked for a system group:\n%s", logs["groupadd"])
	}
	useradd := logs["useradd"]
	for _, want := range []string{"--system", "--gid whichports-agent",
		"--shell /usr/sbin/nologin", "whichports-agent"} {
		if !strings.Contains(useradd, want) {
			t.Errorf("useradd was not asked for %q:\n%s", want, useradd)
		}
	}
}

// Every run after the first must leave the existing user alone. groupadd and
// useradd both fail on an existing name, and postinstall runs on every
// upgrade under set -e, so a missing guard here makes every upgrade fail.
func TestPostinstallLeavesAnExistingUserAlone(t *testing.T) {
	logs := runPostinstall(t, true)
	if logs["groupadd"] != "" {
		t.Errorf("groupadd was called although the group exists:\n%s", logs["groupadd"])
	}
	if logs["useradd"] != "" {
		t.Errorf("useradd was called although the user exists:\n%s", logs["useradd"])
	}
}

// The state directory is handed to the agent user, because timer mode writes
// the host document there and the unit no longer runs as root.
func TestPostinstallHandsTheStateDirectoryToTheAgentUser(t *testing.T) {
	for _, userExists := range []bool{false, true} {
		logs := runPostinstall(t, userExists)
		if !strings.Contains(logs["mkdir"], "-p /var/lib/whichports") {
			t.Errorf("the state directory was not created:\n%s", logs["mkdir"])
		}
		if !strings.Contains(logs["chown"], "whichports-agent:whichports-agent /var/lib/whichports") {
			t.Errorf("the state directory was not handed to the agent user:\n%s", logs["chown"])
		}
		if !strings.Contains(logs["chmod"], "0750 /var/lib/whichports") {
			t.Errorf("the state directory mode was not set:\n%s", logs["chmod"])
		}
	}
}

// The security review of PR 243 reproduced this on the built .deb: postinstall
// ran chown and chmod on paths it had not checked, and both follow a symlink,
// so a link planted at either path had ownership handed through it to whatever
// it pointed at. Planting one already takes root, which is why the severity was
// judged low, but writeFileAtomic in cmd/agent/main.go rejects "unreachable
// given the directory permissions" as a defence in writing, and this scriptlet
// runs as root on every install and every upgrade.
//
// The victim assertions here are physical rather than logged: chmod runs for
// real, so against the unfixed script the victim's mode really was rewritten
// through the link.
func TestPostinstallRefusesASymlinkedStateDirectory(t *testing.T) {
	tree := t.TempDir()
	victim := filepath.Join(tree, "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	// os.Mkdir's mode passes through the umask, so set it explicitly: the
	// assertion below is that this exact mode survives.
	if err := os.Chmod(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(tree, "var-lib-whichports")
	if err := os.Symlink(victim, stateDir); err != nil {
		t.Fatal(err)
	}
	// No enrolment file at all, which is every fresh install.
	confFile := filepath.Join(tree, "agent.conf")

	chownLog, out, err := runPostinstallOnTree(t, stateDir, confFile)
	if err == nil {
		t.Errorf("postinstall completed although the state directory is a symlink:\n%s", out)
	}
	if !strings.Contains(out, "symlink") {
		t.Errorf("the refusal never says what it found:\n%s", out)
	}
	info, statErr := os.Stat(victim)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("the victim directory's mode was rewritten through the link: got %o, want 700", got)
	}
	if strings.Contains(chownLog, stateDir) {
		t.Errorf("chown was pointed at the symlinked state directory:\n%s", chownLog)
	}
}

// The enrolment file half of the same fault. The -f test follows a link too,
// so without its own check a symlink passed as the enrolment file and the
// ownership repair reached through it.
func TestPostinstallRefusesASymlinkedEnrolmentFile(t *testing.T) {
	tree := t.TempDir()
	victim := filepath.Join(tree, "victim")
	if err := os.WriteFile(victim, []byte("not the enrolment file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(tree, "var-lib-whichports")
	confFile := filepath.Join(tree, "agent.conf")
	if err := os.Symlink(victim, confFile); err != nil {
		t.Fatal(err)
	}

	chownLog, out, err := runPostinstallOnTree(t, stateDir, confFile)
	if err == nil {
		t.Errorf("postinstall completed although the enrolment file is a symlink:\n%s", out)
	}
	if !strings.Contains(out, "symlink") {
		t.Errorf("the refusal never says what it found:\n%s", out)
	}
	info, statErr := os.Stat(victim)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("the victim file's mode was rewritten through the link: got %o, want 600", got)
	}
	if strings.Contains(chownLog, confFile) {
		t.Errorf("chown was pointed at the symlinked enrolment file:\n%s", chownLog)
	}
}

// The refusals must never fire on the legitimate shapes: a state directory
// that does not exist yet, one that already does, and a real enrolment file.
// Same run as the stub-based test above, but on a real tree, so the modes are
// measured off the disk rather than read out of a log.
func TestPostinstallHandlesARealTree(t *testing.T) {
	for _, dirExists := range []bool{false, true} {
		t.Run(fmt.Sprintf("dirExists=%v", dirExists), func(t *testing.T) {
			tree := t.TempDir()
			stateDir := filepath.Join(tree, "var-lib-whichports")
			if dirExists {
				if err := os.Mkdir(stateDir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			confFile := filepath.Join(tree, "agent.conf")
			if err := os.WriteFile(confFile, []byte("server=example\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			chownLog, out, err := runPostinstallOnTree(t, stateDir, confFile)
			if err != nil {
				t.Fatalf("postinstall failed on a legitimate tree: %v\n%s", err, out)
			}
			for path, want := range map[string]os.FileMode{stateDir: 0o750, confFile: 0o640} {
				info, statErr := os.Stat(path)
				if statErr != nil {
					t.Fatal(statErr)
				}
				if got := info.Mode().Perm(); got != want {
					t.Errorf("%s has mode %o, want %o", path, got, want)
				}
			}
			for _, path := range []string{stateDir, confFile} {
				if !strings.Contains(chownLog, path) {
					t.Errorf("chown was never pointed at %s:\n%s", path, chownLog)
				}
			}
		})
	}
}

// usrLocalTree is a legitimate state directory and enrolment file beside a
// /usr/local the test shapes itself, for the step that puts /usr/local/bin
// back. It returns the three paths the harness rewrites the script to.
func usrLocalTree(t *testing.T) (stateDir, confFile, usrLocal string) {
	t.Helper()
	tree := t.TempDir()
	usrLocal = filepath.Join(tree, "usr-local")
	if err := os.Mkdir(usrLocal, 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(tree, "var-lib-whichports"), filepath.Join(tree, "agent.conf"), usrLocal
}

// The upgrade from a version before 0.1.12, as measured on Ubuntu 26.04.1 on
// 2026-10-02: the old package listed /usr/local/bin as its own, ours were the
// only files in it, and dpkg deleted the directory while moving the programs
// to /usr/bin. The directory is the administrator's, so the script puts it
// back, in the shape Debian Policy 9.1.2 gives it.
func TestPostinstallPutsBackUsrLocalBinWhenTheUpgradeTookIt(t *testing.T) {
	t.Run("no staff file, so 0755 and root's own", func(t *testing.T) {
		stateDir, confFile, usrLocal := usrLocalTree(t)
		chownLog, out, err := runPostinstallOnTreeWithUsrLocal(t, stateDir, confFile,
			usrLocal, filepath.Join(usrLocal, "no-staff-group-file"))
		if err != nil {
			t.Fatalf("postinstall failed: %v\n%s", err, out)
		}
		bin := filepath.Join(usrLocal, "bin")
		info, statErr := os.Lstat(bin)
		if statErr != nil {
			t.Fatalf("the directory was not put back: %v\n%s", statErr, out)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory: %v", bin, info.Mode())
		}
		if got := info.Mode().Perm(); got != 0o755 {
			t.Errorf("%s has mode %o, want 755", bin, got)
		}
		if info.Mode()&os.ModeSetgid != 0 {
			t.Errorf("%s is set-group-id on a machine with no staff file", bin)
		}
		if strings.Contains(chownLog, bin) {
			t.Errorf("chown was pointed at %s on a machine with no staff file:\n%s", bin, chownLog)
		}
	})

	t.Run("a staff file, so 2775 root:staff", func(t *testing.T) {
		stateDir, confFile, usrLocal := usrLocalTree(t)
		staffFile := filepath.Join(filepath.Dir(usrLocal), "staff-group-for-usr-local")
		if err := os.WriteFile(staffFile, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		chownLog, out, err := runPostinstallOnTreeWithUsrLocal(t, stateDir, confFile, usrLocal, staffFile)
		if err != nil {
			t.Fatalf("postinstall failed: %v\n%s", err, out)
		}
		bin := filepath.Join(usrLocal, "bin")
		info, statErr := os.Lstat(bin)
		if statErr != nil {
			t.Fatalf("the directory was not put back: %v\n%s", statErr, out)
		}
		if got := info.Mode().Perm(); got != 0o775 {
			t.Errorf("%s has mode %o, want 775", bin, got)
		}
		if info.Mode()&os.ModeSetgid == 0 {
			t.Errorf("%s is not set-group-id, and the staff file asks for 2775", bin)
		}
		if !strings.Contains(chownLog, "root:staff "+bin) {
			t.Errorf("the directory was not handed to root:staff:\n%s", chownLog)
		}
	})
}

// Every machine that still has its /usr/local/bin, which is every fresh
// install and every upgrade where the directory held something else as well.
// Nothing about it may change: not its mode, not what is in it.
func TestPostinstallLeavesAnExistingUsrLocalBinAlone(t *testing.T) {
	stateDir, confFile, usrLocal := usrLocalTree(t)
	bin := filepath.Join(usrLocal, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	// An odd mode on purpose, set explicitly because Mkdir's passes through
	// the umask: the assertion is that this exact mode survives.
	if err := os.Chmod(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(bin, "the-admins-own-tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A staff file is present, so a script that forgot its "missing" test
	// would chown and chmod the directory and this would catch it.
	staffFile := filepath.Join(filepath.Dir(usrLocal), "staff-group-for-usr-local")
	if err := os.WriteFile(staffFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	chownLog, out, err := runPostinstallOnTreeWithUsrLocal(t, stateDir, confFile, usrLocal, staffFile)
	if err != nil {
		t.Fatalf("postinstall failed: %v\n%s", err, out)
	}
	info, statErr := os.Stat(bin)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("an existing %s had its mode changed to %o, want 700 as it was", bin, got)
	}
	if _, statErr := os.Stat(tool); statErr != nil {
		t.Errorf("the administrator's own file is gone: %v", statErr)
	}
	if strings.Contains(chownLog, bin) {
		t.Errorf("chown was pointed at an existing %s:\n%s", bin, chownLog)
	}
}

// The shapes where there is nothing to put back, or no way to. None of them
// may fail the install, and none may create anything.
func TestPostinstallNeverFailsOverUsrLocalBin(t *testing.T) {
	t.Run("no /usr/local at all", func(t *testing.T) {
		stateDir, confFile, usrLocal := usrLocalTree(t)
		if err := os.Remove(usrLocal); err != nil {
			t.Fatal(err)
		}
		_, out, err := runPostinstallOnTreeWithUsrLocal(t, stateDir, confFile,
			usrLocal, filepath.Join(usrLocal, "no-staff-group-file"))
		if err != nil {
			t.Fatalf("postinstall failed on a machine with no /usr/local: %v\n%s", err, out)
		}
		if _, statErr := os.Lstat(usrLocal); !os.IsNotExist(statErr) {
			t.Errorf("the script created /usr/local, which is not a package's to create: %v", statErr)
		}
	})

	t.Run("a link where the directory would be", func(t *testing.T) {
		// A link that points nowhere reads as missing to a plain -e test. It
		// is still something the administrator put there.
		stateDir, confFile, usrLocal := usrLocalTree(t)
		bin := filepath.Join(usrLocal, "bin")
		target := filepath.Join(filepath.Dir(usrLocal), "nowhere")
		if err := os.Symlink(target, bin); err != nil {
			t.Fatal(err)
		}
		_, out, err := runPostinstallOnTreeWithUsrLocal(t, stateDir, confFile,
			usrLocal, filepath.Join(usrLocal, "no-staff-group-file"))
		if err != nil {
			t.Fatalf("postinstall failed over a link at /usr/local/bin: %v\n%s", err, out)
		}
		info, statErr := os.Lstat(bin)
		if statErr != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Errorf("the link at %s was replaced or removed: %v %v", bin, info, statErr)
		}
		if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
			t.Errorf("the script created something through the link: %v", statErr)
		}
	})

	t.Run("a /usr/local that cannot be written", func(t *testing.T) {
		// Debian Policy 9.1.2: /usr/local "can be mounted read-only from a
		// remote server". A directory without write permission refuses the
		// mkdir the same way for anyone but root, so as root this run only
		// proves the script still succeeds.
		stateDir, confFile, usrLocal := usrLocalTree(t)
		if err := os.Chmod(usrLocal, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(usrLocal, 0o755) })
		_, out, err := runPostinstallOnTreeWithUsrLocal(t, stateDir, confFile,
			usrLocal, filepath.Join(filepath.Dir(usrLocal), "no-staff-group-file"))
		if err != nil {
			t.Fatalf("a /usr/local that refuses the mkdir failed the install: %v\n%s", err, out)
		}
		if os.Geteuid() != 0 {
			if _, statErr := os.Lstat(filepath.Join(usrLocal, "bin")); !os.IsNotExist(statErr) {
				t.Errorf("a directory appeared inside a read-only /usr/local: %v", statErr)
			}
		}
	})
}

// The bug this whole file exists for. On an upgrade the pre-remove must leave
// the timer exactly as the operator set it. Disabling it here stops the host
// reporting after a routine upgrade, and nothing downstream notices until the
// dead-man sweep fires hours later.
func TestPreremoveKeepsTimerOnUpgrade(t *testing.T) {
	// "upgrade" is deb, "1" is rpm. Both mean: another version remains.
	for _, arg := range []string{"upgrade", "1"} {
		t.Run(arg, func(t *testing.T) {
			calls := runScriptlet(t, "preremove.sh", arg)
			if strings.Contains(calls, "disable") {
				t.Fatalf("pre-remove disabled the timer during an upgrade (arg %q):\n%s",
					arg, calls)
			}
		})
	}
}

// The other half: on a real removal the timer must be stopped and disabled, so
// a removed binary is not left with a timer pointing at it.
func TestPreremoveDisablesTimerOnRemoval(t *testing.T) {
	// "remove" is deb, "0" is rpm. Both mean: the package is going away.
	for _, arg := range []string{"remove", "0"} {
		t.Run(arg, func(t *testing.T) {
			calls := runScriptlet(t, "preremove.sh", arg)
			if !strings.Contains(calls, "disable") {
				t.Fatalf("pre-remove did not disable the timer on removal (arg %q):\n%s",
					arg, calls)
			}
			if !strings.Contains(calls, "whichports-agent.timer") {
				t.Fatalf("pre-remove disabled something other than the timer (arg %q):\n%s",
					arg, calls)
			}
		})
	}
}

// The uninstaller is shipped in the package, so removing the agent needs no
// network. Measured behaviour it answers is in docs/PRODUCT.md 4f: a package
// removal leaves the enrolment credential, the state directory, the package
// source and the signing key behind.
func TestUninstallIsShippedAndIsValidShell(t *testing.T) {
	script, err := filepath.Abs("uninstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(script); statErr != nil {
		t.Fatalf("the uninstaller is missing: %v", statErr)
	}
	// sh -n parses without executing. This runs on a developer machine, so it
	// must never be run for real.
	out, runErr := exec.Command("sh", "-n", script).CombinedOutput()
	if runErr != nil {
		t.Fatalf("uninstall.sh is not valid sh: %v\n%s", runErr, out)
	}

	body, readErr := os.ReadFile(script)
	if readErr != nil {
		t.Fatal(readErr)
	}
	text := string(body)

	// Every path the installer writes has to be named here, or the thing it
	// leaves behind is the thing this script exists to remove.
	for _, path := range []string{
		"/etc/whichports",
		"/var/lib/whichports",
		"/etc/apt/sources.list.d/whichports.list",
		"/usr/share/keyrings/whichports.gpg",
		"/etc/yum.repos.d/whichports.repo",
		"/etc/pki/rpm-gpg/RPM-GPG-KEY-whichports",
	} {
		if !strings.Contains(text, path) {
			t.Errorf("uninstall.sh never mentions %s", path)
		}
	}

	// It must say that deleting the credential is not revoking the host. The
	// credential is ours rather than theirs (SI-5) and revocation lives in the
	// dashboard, so an operator who reads only this output must not come away
	// believing the host can no longer report.
	if !strings.Contains(text, "revoke") && !strings.Contains(text, "Revoke") {
		t.Error("uninstall.sh does not tell the operator to revoke the host")
	}

	// Removing the package last is deliberate: this script ships inside it.
	// The command, not the header comment, which mentions apt-get purge while
	// explaining what a plain removal leaves behind.
	confIdx := strings.Index(text, `rm -rf "$CONF_DIR"`)
	pkgIdx := strings.Index(text, "apt-get purge -y whichports-agent")
	if confIdx < 0 || pkgIdx < 0 || pkgIdx < confIdx {
		t.Error("the package must be removed after the files, or the script can be deleted mid-run")
	}
}

// The closing message says what is left to do, rather than the same four lines
// on every install and every upgrade. The owner, reading the output of a fleet
// upgrade on 2026-08-22: the banner told an operator whose hosts had been
// reporting for months to enrol them and to enable a timer that was already on.
//
// The timer half is asserted here. The enrolment half needs a real
// /etc/whichports/agent.conf, so it is asserted in ops/cleanbox against a
// container that has one.
func TestPostinstallDoesNotTellYouToEnableATimerThatIsOn(t *testing.T) {
	_, out := runPostinstallWithTimer(t, true, true)
	if strings.Contains(out, "systemctl enable --now") {
		t.Errorf("the banner told the operator to enable a timer that is already enabled:\n%s", out)
	}
	if !strings.Contains(out, "already enabled") {
		t.Errorf("the banner said nothing about the timer it found:\n%s", out)
	}
}

// And it still says it when the timer is off, which is every first install and
// was also every host in the fleet immediately after the 0.1.5 to 0.1.6
// upgrade, because that upgrade ran the old unguarded pre-remove.
func TestPostinstallStillSaysHowToEnableATimerThatIsOff(t *testing.T) {
	_, out := runPostinstallWithTimer(t, false, false)
	if !strings.Contains(out, "systemctl enable --now whichports-agent.timer") {
		t.Errorf("a host with no timer was not told how to start one:\n%s", out)
	}
	if strings.Contains(out, "already enabled") {
		t.Errorf("the banner claimed a timer that is not enabled:\n%s", out)
	}
}

// A host that has never enrolled is still told how, on every run, because that
// is the one instruction it genuinely still needs.
func TestPostinstallTellsAnUnenrolledHostHowToConnect(t *testing.T) {
	_, out := runPostinstallWithTimer(t, false, false)
	if !strings.Contains(out, "whichports-agent enroll") {
		t.Errorf("a host with no enrolment was not told how to connect:\n%s", out)
	}
}

// With enroll, the installer connects the server right after the package is
// installed: it enrols, turns the timer on and collects once. The package's
// closing lines used to say to do both just before the installer did them,
// the confusion of docs/RECORD.md 4.184. The installer says so in
// WHICHPORTS_INSTALLER_CONNECTS, and the package then leaves the timer and
// the enrolment to the installer's own last lines (docs/RECORD.md 4.460).
func TestPostinstallLeavesWhatTheInstallerDoesNextToTheInstaller(t *testing.T) {
	t.Setenv("WHICHPORTS_INSTALLER_CONNECTS", "yes")
	_, out := runPostinstallWithTimer(t, false, false)
	for _, said := range []string{"systemctl enable --now", "whichports-agent enroll", "already enabled", "enrolled already"} {
		if strings.Contains(out, said) {
			t.Errorf("the installer connects next and the package still says %q:\n%s", said, out)
		}
	}
	if !strings.Contains(out, "whichports-agent installed.") {
		t.Errorf("the package no longer says it was installed:\n%s", out)
	}
}

// Any other value, and an install by hand, keep the lines as they were.
func TestPostinstallKeepsItsLinesForAnyoneElse(t *testing.T) {
	for _, value := range []string{"no", "", "YES"} {
		t.Run("value="+value, func(t *testing.T) {
			t.Setenv("WHICHPORTS_INSTALLER_CONNECTS", value)
			_, out := runPostinstallWithTimer(t, false, false)
			if !strings.Contains(out, "systemctl enable --now whichports-agent.timer") ||
				!strings.Contains(out, "whichports-agent enroll") {
				t.Errorf("with %q the package dropped what is left to do:\n%s", value, out)
			}
		})
	}
}
