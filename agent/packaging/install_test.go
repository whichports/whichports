package packaging

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

// These tests read the installer that get.whichports.com serves. They need no
// container and no network, so they run in the everyday suite, which matters:
// the full clean-box test in ops/cleanbox takes minutes and is gated behind an
// environment variable, and these four facts are cheap enough to check on every
// run.
//
// What they are guarding is a fault this project has already had a version of.
// docs/RECORD.md 4.48 found a production host with no whichports package source
// configured at all, quietly unable to upgrade. The class is the same here: a
// constant in the installer that stops agreeing with reality, and nothing that
// notices.

// installerSource reads the shipped installer.
func installerSource(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("reading install.sh: %v", err)
	}
	return string(data)
}

// valueOf pulls the value out of a shell assignment such as KEY_FPR="...". It
// fails rather than returning empty, because a silent empty string here would
// turn every assertion below into a comparison of nothing with nothing.
func valueOf(t *testing.T, script, name string) string {
	t.Helper()
	prefix := name + "=\""
	idx := strings.Index(script, "\n"+prefix)
	if idx < 0 {
		t.Fatalf("install.sh has no %s= assignment, so the installer has changed "+
			"shape and these tests must be updated to match", name)
	}
	rest := script[idx+len(prefix)+1:]
	end := strings.Index(rest, "\"")
	if end <= 0 {
		t.Fatalf("could not read the value of %s from install.sh", name)
	}
	return rest[:end]
}

// The installer refuses any signing key whose fingerprint is not this one. If
// the key in this repository is ever rotated and the installer is not updated
// with it, every install stops with a mismatch, and the first person to find out
// should not be an operator.
func TestInstallerPinsTheCommittedSigningKey(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Fatal("gpg is required to read the signing key fingerprint and was not found. " +
			"It is the same tool the installer itself uses, and it is needed to sign a " +
			"release, so a machine that builds this project has it.")
	}
	const keyPath = "signing/whichports-signing-public.asc"
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected the published public key at %s: %v", keyPath, err)
	}
	out, err := exec.Command("gpg", "--with-colons", "--show-keys", keyPath).Output()
	if err != nil {
		t.Fatalf("gpg could not read %s: %v", keyPath, err)
	}
	var fromKey string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "fpr:") {
			fields := strings.Split(line, ":")
			if len(fields) > 9 {
				fromKey = fields[9]
			}
			break
		}
	}
	if len(fromKey) != 40 {
		t.Fatalf("could not read a fingerprint out of %s, gpg said:\n%s", keyPath, out)
	}
	if pinned := valueOf(t, installerSource(t), "KEY_FPR"); pinned != fromKey {
		t.Errorf("the installer pins a fingerprint that is not the committed key's.\n"+
			"  install.sh: %s\n  %s: %s", pinned, keyPath, fromKey)
	}
}

// The one line the page tells a stranger to run points at this host over https.
// A plain http base, or a different host, would be a change nobody should be
// able to make without a test objecting.
func TestInstallerFetchesOverHTTPS(t *testing.T) {
	base := valueOf(t, installerSource(t), "BASE")
	if base != "https://get.whichports.com" {
		t.Errorf("the installer base URL is %q, want https://get.whichports.com", base)
	}
}

// Both package managers must be pointed at the key file on local disk rather
// than at a URL. This is the protection that survives a compromise of
// get.whichports.com: whoever took the site can serve a new key, but neither
// apt nor dnf will go and fetch one.
func TestInstallerPinsPackageManagersToALocalKey(t *testing.T) {
	script := installerSource(t)
	if !strings.Contains(script, "signed-by=$KEYRING_DEB") {
		t.Error("the apt source line is not pinned with signed-by to the local keyring")
	}
	if !strings.Contains(script, "gpgkey=file://$KEYRING_RPM") {
		t.Error("the dnf repository does not point gpgkey at a local file")
	}
	if strings.Contains(script, "gpgkey=http") {
		t.Error("the dnf repository points gpgkey at a URL, so dnf could import a " +
			"rotated key later and accept packages signed with it")
	}
	for _, want := range []string{"gpgcheck=1", "repo_gpgcheck=1"} {
		if !strings.Contains(script, want) {
			t.Errorf("the dnf repository is missing %q", want)
		}
	}
}

// Order matters, not just presence. The script is piped into sh as root, so
// every refusal has to happen before the first thing that changes the machine.
// A root check that ran after the repository was written would leave a
// half-configured package manager behind.
func TestInstallerRefusesBeforeItTouchesTheMachine(t *testing.T) {
	script := installerSource(t)
	rootCheck := strings.Index(script, `[ "$(id -u)" = "0" ]`)
	gpgCheck := strings.Index(script, "gpg not found")
	archCheck := strings.Index(script, `[ "$ARCH" = "x86_64" ]`)
	// The fetch itself, not the one-liner quoted in the script's own header
	// comment. Searching for "curl -fsSL" finds the comment on line 4 and makes
	// this test fail against a correct installer, which is how it was written
	// the first time.
	firstFetch := strings.Index(script, `curl -fsSL "$KEY_URL"`)
	fprCheck := strings.Index(script, "signing key fingerprint mismatch")
	firstWrite := strings.Index(script, "configuring the apt repository")

	for name, idx := range map[string]int{
		"the root check":        rootCheck,
		"the gpg check":         gpgCheck,
		"the machine check":     archCheck,
		"the key fetch":         firstFetch,
		"the fingerprint check": fprCheck,
		"the first repo config": firstWrite,
	} {
		if idx < 0 {
			t.Fatalf("%s is not in install.sh, so this ordering test would prove nothing", name)
		}
	}
	if !(rootCheck < gpgCheck && gpgCheck < firstFetch) {
		t.Error("install.sh checks for root and gpg after it starts fetching")
	}
	if !(archCheck < firstFetch) {
		t.Error("install.sh checks the machine after it starts fetching")
	}
	if !(fprCheck < firstWrite) {
		t.Error("install.sh configures a package manager before checking the key fingerprint")
	}
}

// The installer takes no arguments, or `enroll` with the agent's own enrol
// flags, and everything else is refused. Every case runs the real script,
// which is what makes them more than string matching: an argument has to
// stop it before the root check, and no case can reach the network, because
// TestInstallerRefusesBeforeItTouchesTheMachine pins the fetch to after the
// refusals. The second case is the flag that existed until 0.1.10: an old
// add-server page or a shell history may still carry it, and it must fail
// loudly rather than install an agent narrower than the command asked for.
func TestInstallerArgumentParsing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, so the script would get past its root check " +
			"and try to reach the real repository")
	}
	refused := []struct {
		name string
		args []string
		says string
	}{
		{"enroll_with_nothing_after_it", []string{"enroll"}, "needs both --server= and --credential="},
		{"enroll_without_a_credential", []string{"enroll", "--server=https://app.example.invalid"},
			"needs both --server= and --credential="},
		{"enroll_without_a_server", []string{"enroll", "--credential=whp_cleanbox0123456789abcdefghijklmnop"},
			"needs both --server= and --credential="},
		{"enroll_with_an_empty_credential", []string{"enroll", "--server=https://app.example.invalid", "--credential="},
			"unknown argument: --credential="},
		{"enroll_with_a_credential_of_the_wrong_shape", []string{"enroll",
			"--server=https://app.example.invalid", "--credential=hello"},
			"the credential is not one the dashboard hands out"},
		{"enroll_with_a_flag_the_installer_does_not_pass_on", []string{"enroll",
			"--server=http://10.0.0.5", "--credential=whp_cleanbox0123456789abcdefghijklmnop", "--allow-http"},
			"unknown argument: --allow-http"},
		{"enroll_with_the_agents_mode_flag", []string{"enroll",
			"--server=https://app.example.invalid", "--credential=whp_cleanbox0123456789abcdefghijklmnop", "--mode=stdout"},
			"unknown argument: --mode=stdout"},
		{"a_value_given_as_its_own_word", []string{"enroll", "--server", "https://app.example.invalid",
			"--credential=whp_cleanbox0123456789abcdefghijklmnop"}, "unknown argument: --server"},
		{"enroll_that_is_not_the_first_word", []string{"--server=https://app.example.invalid", "enroll"},
			"unknown argument: --server=https://app.example.invalid"},
		{"another_command", []string{"uninstall"}, "unknown argument: uninstall"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			out, err := exec.Command("sh", append([]string{"install.sh"}, tc.args...)...).CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 2 {
				t.Fatalf("install.sh %v did not stop with status 2: %v\n%s", tc.args, err, out)
			}
			if !strings.Contains(string(out), tc.says) {
				t.Errorf("the refusal of %v never says %q:\n%s", tc.args, tc.says, out)
			}
			if strings.Contains(string(out), "run as root") {
				t.Errorf("install.sh %v got as far as its root check, so the "+
					"arguments were accepted:\n%s", tc.args, out)
			}
		})
	}
	// The other side: what the Add server window hands out is accepted, and
	// here that means the script gets past its arguments to the root check.
	accepted := []struct {
		name string
		args []string
	}{
		{"no_arguments", nil},
		{"enroll_as_the_window_writes_it", []string{"enroll", "--server=https://app.example.invalid",
			"--credential=whp_cleanbox0123456789abcdefghijklmnop"}},
		{"enroll_with_the_flags_the_other_way_round", []string{"enroll",
			"--credential=whp_cleanbox0123456789abcdefghijklmnop", "--server=https://app.example.invalid"}},
		{"enroll_from_a_self_hosted_instance_that_uses_our_probers", []string{"enroll",
			"--server=https://selfhosted.example.invalid", "--credential=whp_cleanbox0123456789abcdefghijklmnop",
			"--prober-server=https://app.example.invalid", "--prober-proof-key=whpp_x"}},
	}
	for _, tc := range accepted {
		args := tc.args
		t.Run("accepted_"+tc.name, func(t *testing.T) {
			out, err := exec.Command("sh", append([]string{"install.sh"}, args...)...).CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(out), "run as root") {
				t.Fatalf("install.sh %v did not reach its root check: %v\n%s", args, err, out)
			}
			if strings.Contains(string(out), "unknown argument") {
				t.Errorf("install.sh refused arguments the Add server window hands out:\n%s", out)
			}
		})
	}
	t.Run("unknown_argument_is_refused", func(t *testing.T) {
		out, err := exec.Command("sh", "install.sh", "--bogus").CombinedOutput()
		if err == nil {
			t.Fatalf("install.sh accepted an argument it does not know:\n%s", out)
		}
		if !strings.Contains(string(out), "unknown argument") {
			t.Errorf("the refusal never names the problem:\n%s", out)
		}
	})
	t.Run("the_retired_full_visibility_flag_is_refused", func(t *testing.T) {
		out, err := exec.Command("sh", "install.sh", "--full-visibility").CombinedOutput()
		if err == nil {
			t.Fatalf("install.sh accepted the retired flag:\n%s", out)
		}
		if !strings.Contains(string(out), "takes no arguments") {
			t.Errorf("the refusal never says the installer takes no arguments:\n%s", out)
		}
	})
}

// The installer widens the unit by nothing since 0.1.10: it names no
// capability and writes no drop-in, because the unit behind a port comes
// from the kernel at no privilege (docs/AGENT-PRIVILEGE.md 4a). What it does
// apply, since 2026-09-13, is read grants on the files the Rules tab's
// declared side is read from (record 4.176), and this test holds those to
// exactly read: never a w in a grant, never the docker group, never the
// podman socket, which are write access to a runtime and stay the
// operator's own lines.
func TestInstallerWidensTheUnitByNothingAndGrantsReadOnly(t *testing.T) {
	script := installerSource(t)
	for _, forbidden := range []string{"CAP_", "full-visibility.conf",
		"AmbientCapabilities", "CapabilityBoundingSet", "usermod -aG docker",
		"/run/podman", "docker.sock"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("install.sh contains %q, so the installer widens the unit or the host again", forbidden)
		}
	}
	// Every grant call in the script, with the permission it hands out.
	grants := 0
	for _, line := range strings.Split(script, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "grant" {
			continue
		}
		grants++
		if fields[1] != "r" && fields[1] != "rx" {
			t.Errorf("install.sh grants %q on %s, and only r or rx is a read grant", fields[1], fields[2])
		}
		if !strings.HasPrefix(fields[2], "/etc/ufw/") && !strings.HasPrefix(fields[2], "/etc/firewalld") && fields[2] != `"$zone"` {
			t.Errorf("install.sh grants on %s, outside ufw's and firewalld's files", fields[2])
		}
	}
	if grants == 0 {
		t.Fatal("install.sh applies no read grant, so a fresh ufw host reads its rules as not readable")
	}
	// The one call site that does the granting looks at a symlink first, so
	// the installer never follows a link to a file it was not asked about.
	// Which links it follows and which it refuses is run for real in
	// grant_test.go. This only holds the check in place.
	if !strings.Contains(script, `if [ -L "$path" ]; then`) {
		t.Error("install.sh's grant no longer checks for a symlink target")
	}
}

// One list of grant targets, five files that must agree on it. install.sh
// and ops/upgrade-agent.sh apply the read grants on ufw's and firewalld's
// files, README.md documents them and the runtime grants an operator applies
// by hand, and postremove.sh and uninstall.sh take every one of them back, so
// a path in one and forgotten in another is a grant that outlives its
// removal. The drop-in is on the removers' list because an installer before
// 0.1.10 wrote it and a host widened then still carries it. README.md owns
// the list, and this test only holds the copies together.
func TestGrantTargetsAgreeAcrossScripts(t *testing.T) {
	readTargets := []string{
		"/etc/ufw/user.rules",
		"/etc/ufw/user6.rules",
		"/etc/firewalld/zones/*.xml",
		"/etc/firewalld/firewalld.conf",
	}
	removerOnly := []string{
		"/etc/systemd/system/whichports-agent.service.d/full-visibility.conf",
		"/run/podman/podman.sock",
	}
	for _, file := range []string{"install.sh", "../../ops/upgrade-agent.sh"} {
		if file != "install.sh" {
			// The upgrade script lives in the repository's own ops directory,
			// outside agent/. A tree that holds agent/ and no such directory
			// has no second copy to hold to the list. Where the directory
			// exists the script must be in it.
			if _, statErr := os.Stat("../../ops"); os.IsNotExist(statErr) {
				continue
			}
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		for _, target := range readTargets {
			if !strings.Contains(string(data), target) {
				t.Errorf("%s never grants on %s, so a fresh host reads it as not readable", file, target)
			}
		}
	}
	targets := append(append([]string{}, readTargets...), removerOnly...)
	files := []string{"scripts/postremove.sh", "uninstall.sh", "../README.md"}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		text := string(data)
		for _, target := range targets {
			// uninstall.sh builds the drop-in path from a directory variable
			// and the file name, so the joined literal never appears. Both
			// halves are checked instead.
			if file == "uninstall.sh" && strings.Contains(target, "full-visibility.conf") {
				dir, name, _ := strings.Cut(target, "/full-visibility")
				if !strings.Contains(text, dir) || !strings.Contains(text, "full-visibility"+name) {
					t.Errorf("%s does not name both halves of %s", file, target)
				}
				continue
			}
			if !strings.Contains(text, target) {
				t.Errorf("%s never mentions %s, so the four widening files have "+
					"drifted apart", file, target)
			}
		}
		// The docker grant is a group rather than a path. README.md documents
		// it as usermod -aG and the two removers take it back with gpasswd.
		if file == "../README.md" {
			if !strings.Contains(text, "usermod -aG docker whichports-agent") {
				t.Errorf("%s no longer documents the docker group grant", file)
			}
			continue
		}
		if !strings.Contains(text, "gpasswd -d whichports-agent docker") {
			t.Errorf("%s never takes the docker group membership back", file)
		}
	}
}

// The installer lets unattended-upgrades upgrade the agent on apt hosts, by
// default (the owner, 2026-09-10: nobody opts in to upgrades). Ubuntu's own
// allow-list is the distribution's pockets only, and the repository publishes
// Origin whichports, Suite stable, so without the drop-in the agent is never
// upgraded by the machine. The origin string here has to match what
// packaging/repo/build-repo.sh stamps, which the second test reads from that
// script rather than restating.
func TestInstallerAllowsUnattendedUpgradesFromOurRepository(t *testing.T) {
	script := installerSource(t)
	if !strings.Contains(script, `APT_UNATTENDED="/etc/apt/apt.conf.d/51whichports"`) {
		t.Fatal("install.sh no longer names the unattended-upgrades drop-in")
	}
	if !strings.Contains(script, `"whichports:stable";`) {
		t.Fatal("the drop-in does not allow the origin whichports:stable")
	}
	if !strings.Contains(script, "Unattended-Upgrade::Allowed-Origins") {
		t.Fatal("the drop-in is not an Allowed-Origins block")
	}
	// The rpm branch says the line rather than switching the whole system.
	if !strings.Contains(script, "dnf-automatic") {
		t.Fatal("the dnf branch no longer tells the operator about dnf-automatic")
	}
}

func TestTheAllowedOriginMatchesWhatTheRepositoryPublishes(t *testing.T) {
	repo, err := os.ReadFile("repo/build-repo.sh")
	if err != nil {
		t.Fatalf("reading repo/build-repo.sh: %v", err)
	}
	for _, want := range []string{`ORIGIN="${ORIGIN:-whichports}"`, `SUITE="${SUITE:-stable}"`} {
		if !strings.Contains(string(repo), want) {
			t.Fatalf("build-repo.sh no longer sets %s, so whichports:stable in install.sh may not match", want)
		}
	}
}

func TestUninstallerRemovesTheUnattendedUpgradesDropIn(t *testing.T) {
	data, err := os.ReadFile("uninstall.sh")
	if err != nil {
		t.Fatalf("reading uninstall.sh: %v", err)
	}
	script := string(data)
	if !strings.Contains(script, `APT_UNATTENDED="/etc/apt/apt.conf.d/51whichports"`) {
		t.Fatal("uninstall.sh does not name the drop-in install.sh writes")
	}
	if !strings.Contains(script, `"$APT_UNATTENDED"`) || !strings.Contains(script, "rm -f") {
		t.Fatal("uninstall.sh does not remove the drop-in")
	}
}

// debDependencies reads the deb package's depends list out of nfpm.yaml, line
// by line and with no YAML library, because the block is four lines whose exact
// shape this function checks as it goes. It fails rather than returning an
// empty list, which would make the test below pass by checking nothing.
func debDependencies(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("nfpm.yaml")
	if err != nil {
		t.Fatalf("reading nfpm.yaml: %v", err)
	}
	var deps []string
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case line == "overrides:":
			section = "overrides"
		case section == "overrides" && line == "  deb:":
			section = "deb"
		case section == "deb" && line == "    depends:":
			section = "depends"
		case section == "depends" && strings.HasPrefix(line, "      - "):
			deps = append(deps, strings.TrimSpace(strings.TrimPrefix(line, "      - ")))
		case section == "depends":
			section = "done"
		}
	}
	if len(deps) == 0 {
		t.Fatal("found no deb depends under overrides in nfpm.yaml, so the file has " +
			"changed shape and this test must be updated to match")
	}
	return deps
}

// A dependency from the distribution's archive can only be downloaded while the
// distribution's package lists are on the box, and the installer's first update
// refreshes its own list only. So every deb dependency a box may lack has to be
// one the installer checks for, and refreshes every list for, before it installs
// the agent. acl was added on 2026-09-13 without that, and an install on a box
// with empty lists failed from then until 2026-09-29, unseen, because the
// clean-box run that says so was not running anywhere.
//
// passwd is the one exemption: it is Priority required, so every Debian-family
// install has it. Read with dpkg-query in the clean-box Ubuntu image on
// 2026-09-29, where acl was unknown to dpkg and the list directory was empty.
func TestInstallerRefreshesTheDistributionListsForEachDependency(t *testing.T) {
	script := installerSource(t)
	install := strings.Index(script, "apt-get install -y whichports-agent")
	if install < 0 {
		t.Fatal("install.sh has no apt-get install of the agent, so the installer has " +
			"changed shape and this test must be updated to match")
	}
	for _, dep := range debDependencies(t) {
		if dep == "passwd" {
			continue
		}
		check := strings.Index(script, "dpkg-query -W -f='${Status}' "+dep+" ")
		if check < 0 || check > install {
			t.Errorf("%s is a deb dependency and install.sh does not check for it before "+
				"installing the agent, so a box with empty package lists cannot download it", dep)
			continue
		}
		// The full update: its own line, no options, between the check and the
		// install. The first update ends its line with a backslash instead.
		refresh := strings.Index(script[check:], "apt-get update\n")
		if refresh < 0 || check+refresh > install {
			t.Errorf("install.sh checks for %s but does not refresh every package list "+
				"between that check and installing the agent", dep)
		}
	}
}

// A system with neither apt nor dnf is not supported, and the installer says
// so. openSUSE is one, and it is not supported for now by decision
// (docs/RECORD.md 4.339). Until 2026-10-03 the refusal named two addresses to
// take a package from by hand, and both answered 404.
//
// The script is run for real here, as root would run it, on a machine made of
// stand-ins: PATH is one directory that holds an id that answers 0, a gpg
// that answers the pinned fingerprint, a curl that fetches nothing, and a
// zypper and an rpm that only write down that they were called. No apt-get
// and no dnf. Nothing real is reachable, so this is safe where the test
// itself runs as root.
func TestInstallerRefusesASystemWithoutAptOrDnf(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell scripts are not exercised on Windows")
	}
	script := installerSource(t)
	pinned := regexp.MustCompile(`(?m)^KEY_FPR="([0-9A-F]{40})"$`).FindStringSubmatch(script)
	if pinned == nil {
		t.Fatal("install.sh pins no fingerprint, so the stand-in gpg has nothing to answer")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "calls.log")
	logged := "printf '%s\\n' \"$0 $*\" >> " + shellQuote(log) + "\n"
	stubs := map[string]string{
		"id":     "echo 0\n",
		"uname":  "echo x86_64\n",
		"curl":   logged + "exit 0\n",
		"gpg":    logged + "echo 'fpr:::::::::" + pinned[1] + ":'\n",
		"zypper": logged + "exit 0\n",
		"rpm":    logged + "exit 0\n",
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatalf("writing the %s stand-in: %v", name, err)
		}
	}
	// The three real tools the script uses before it reaches the branch.
	for _, tool := range []string{"mktemp", "rm", "awk"} {
		real, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("this machine has no %s: %v", tool, err)
		}
		if err := os.Symlink(real, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("this machine has no sh: %v", err)
	}

	cmd := exec.Command(shell, "install.sh")
	cmd.Env = []string{"PATH=" + bin}
	out, runErr := cmd.CombinedOutput()

	var exit *exec.ExitError
	if !errors.As(runErr, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("install.sh did not stop with status 1: %v\n%s", runErr, out)
	}
	said := string(out)
	want := "no apt or dnf found. This system is not supported, and nothing was installed."
	if !strings.Contains(said, want) {
		t.Errorf("the refusal never says %q:\n%s", want, said)
	}
	// It names nothing to fetch. The two addresses it used to print answered
	// 404, and an address in a refusal is an instruction.
	for _, gone := range []string{"by hand", "http", "/deb/", "/rpm/", "pool/main"} {
		if strings.Contains(said, gone) {
			t.Errorf("the refusal still says %q:\n%s", gone, said)
		}
	}

	// And nothing was installed: the key was fetched and checked, and no
	// package manager of any kind was asked for anything.
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("reading what was called: %v", err)
	}
	calls := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(calls) != 2 {
		t.Fatalf("want the key fetched and the key checked and nothing else, got:\n%s", data)
	}
	if !strings.HasPrefix(calls[0], filepath.Join(bin, "curl")+" -fsSL https://get.whichports.com/whichports-signing-public.asc -o ") {
		t.Errorf("the first call is not the key fetch: %s", calls[0])
	}
	if !strings.HasPrefix(calls[1], filepath.Join(bin, "gpg")+" --with-colons --show-keys ") {
		t.Errorf("the second call is not the key check: %s", calls[1])
	}
	// The key's temporary file is taken away again on the way out. It is
	// wherever this machine's mktemp puts one, which on a Mac is not TMPDIR.
	keyFile := calls[1][strings.LastIndex(calls[1], " ")+1:]
	if _, statErr := os.Stat(keyFile); !os.IsNotExist(statErr) {
		t.Errorf("the fetched key is still on disk at %s", keyFile)
	}
}

// Our repository publishes the agent for x86_64 alone (nfpm.yaml's arch,
// amd64, and build-repo.sh's ARCH), so on any other machine apt or dnf found
// no package after the repository had been written, and said only that
// (second big test, on an arm64 server). The installer refuses such a machine
// first, in one line that names what it found, before it fetches or writes
// anything. The machine is a stand-in, as above: a uname that answers each
// architecture, and a curl and a gpg that only write down that they ran.
func TestInstallerRefusesAMachineThatIsNotX86_64(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell scripts are not exercised on Windows")
	}
	nfpm, err := os.ReadFile("nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(nfpm), "\narch: \"amd64\"\n") {
		t.Fatal("the package is no longer built for amd64 alone, so the installer's check has to change with it")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("this machine has no sh: %v", err)
	}
	for _, machine := range []string{"aarch64", "armv7l", "i686", "riscv64", "s390x", "ppc64le"} {
		t.Run(machine, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(dir, "calls.log")
			logged := "printf '%s\\n' \"$0 $*\" >> " + shellQuote(log) + "\n"
			stubs := map[string]string{
				"id":      "echo 0\n",
				"uname":   "[ \"$1\" = -m ] && echo " + machine + "\n",
				"curl":    logged + "exit 0\n",
				"gpg":     logged + "exit 0\n",
				"apt-get": logged + "exit 0\n",
				"dnf":     logged + "exit 0\n",
				"mktemp":  logged + "exit 0\n",
			}
			for name, body := range stubs {
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
					t.Fatalf("writing the %s stand-in: %v", name, err)
				}
			}
			cmd := exec.Command(shell, "install.sh")
			cmd.Env = []string{"PATH=" + bin}
			out, runErr := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(runErr, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("install.sh did not stop with status 1: %v\n%s", runErr, out)
			}
			said := strings.TrimSpace(string(out))
			want := "this machine is " + machine + ", and the agent is published for x86_64 only. Nothing was installed."
			if said != want {
				t.Errorf("install.sh said %q, want the one line %q", said, want)
			}
			if data, err := os.ReadFile(log); err == nil {
				t.Errorf("install.sh ran something before it refused:\n%s", data)
			}
		})
	}
}
