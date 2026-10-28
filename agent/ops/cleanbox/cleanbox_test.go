package cleanbox

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCleanBoxInstall walks one box per family through the whole life of an
// installation: install, upgrade, remove, purge. Each stage is its own assertion
// rather than one "it worked", because docs/RECORD.md 4.48 is a case where the
// install was fine, the upgrade was not, and a single end-to-end check would
// have said yes.
//
// The stages share one box on purpose. An upgrade can only be tested on a host
// that was installed first, and a removal only on a host that was upgraded, so
// the order is the point. A failed stage stops the rest, because assertions made
// after an unknown state are noise.
func TestCleanBoxInstall(t *testing.T) {
	f := requireFixture(t)
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			served := f.serve(t, f.repoOld)
			b := startBox(t, fam, fam.image, served)

			stage := func(name string, fn func(t *testing.T)) {
				if !t.Run(name, fn) {
					t.Fatalf("stage %q failed, so the stages after it were not run", name)
				}
			}

			stage("1_installer_runs_to_completion", func(t *testing.T) {
				out := b.mustInstall()
				// The script's own account of what it did. If it ever stops
				// saying these, the operator's next step disappears with them.
				for _, want := range []string{
					"signing key verified: " + f.keyFPR,
					"installing whichports-agent",
					"installed. Next steps:",
					"systemctl enable --now whichports-agent.timer",
				} {
					if !strings.Contains(out, want) {
						t.Errorf("the installer never said %q. Full output:\n%s", want, out)
					}
				}
			})

			stage("2_repository_is_configured_and_the_package_came_from_it", func(t *testing.T) {
				assertRepositoryConfigured(t, b, f)
			})

			stage("3_binary_is_the_one_inside_the_package", func(t *testing.T) {
				b.mustExist("/usr/bin/whichports-agent", "the package ships it")
				mode := strings.TrimSpace(b.mustRun("stat", "-c", "%a %U:%G",
					"/usr/bin/whichports-agent"))
				if mode != "755 root:root" {
					t.Errorf("binary is %q, want 755 root:root", mode)
				}
				got := strings.Fields(b.mustRun("sha256sum", "/usr/bin/whichports-agent"))
				if len(got) == 0 || got[0] != f.binarySHA {
					t.Errorf("the installed binary is not the one that went into the package.\n"+
						"  on the box:  %v\n  in the build: %s", got, f.binarySHA)
				}
				if v := b.installedVersion(); v != oldVersion {
					t.Errorf("package manager reports version %q, want %q", v, oldVersion)
				}
				// The agent can now be asked what it is, so this is the stronger
				// identity check the previous version of this stage asked for.
				//
				// It matters because of the fault 4.48 found on the old VPS: a
				// hand-placed binary under a correct package record could not be
				// told apart from the real thing by looking. The package manager's
				// record is a claim about what was installed. The binary's own
				// answer is a claim by the artefact itself. Only when the two
				// agree has anything been established, and asserting both is what
				// makes the hash comparison above about the build tree rather than
				// the only evidence there is.
				out, err := b.run("/usr/bin/whichports-agent", "--version")
				if err != nil {
					t.Fatalf("the agent could not be asked what it is: %v\n%s", err, out)
				}
				line := strings.TrimSpace(out)
				if !strings.Contains(line, "version="+oldVersion) {
					t.Errorf("the binary calls itself something else than the package "+
						"manager does.\n  binary:  %s\n  package: %s", line, oldVersion)
				}
				// The revision is the other half of 4.63, where a published
				// package had to be traced by unpacking it and reading the build
				// info by hand. A release binary that cannot say which commit it
				// came from is the thing that made that necessary.
				if strings.Contains(line, "vcs.revision=unknown") {
					t.Errorf("the packaged binary does not record the commit it was "+
						"built from, so a published artefact could not be traced back "+
						"to source (docs/RECORD.md 4.63): %s", line)
				}
			})

			stage("3b_sudo_finds_both_programs_by_name", func(t *testing.T) {
				assertSudoFindsBothPrograms(t, b, oldVersion)
			})

			stage("4_units_installed_and_timer_left_off", func(t *testing.T) {
				assertUnitsAfterInstall(t, b)
			})

			stage("5_service_runs_as_its_own_user_with_two_capabilities", func(t *testing.T) {
				assertServiceIdentity(t, b)
			})

			stage("6_collection_succeeds_under_the_tightened_unit", func(t *testing.T) {
				assertCollectionUnderUnit(t, b)
			})

			stage("6b_read_grants_are_entries_and_a_second_install_converges", func(t *testing.T) {
				assertReadGrants(t, b)
			})

			stage("7_upgrade_keeps_the_timer_and_the_enrolment", func(t *testing.T) {
				assertUpgradeKeepsState(t, b, f, served)
			})

			stage("8_removal_and_purge", func(t *testing.T) {
				assertRemoval(t, b)
			})
		})
	}
}

// assertSudoFindsBothPrograms runs the two commands a customer is handed, the
// way they are handed: `sudo whichports-agent ...` from the Add server window
// and `sudo whichports-uninstall` from the Remove window, by name.
//
// It exists because every other stage here calls the agent by its full path,
// and that is how this fault went unseen. Until 0.1.12 the programs were in
// /usr/local/bin, which sudo's secure_path leaves out on the RHEL family, so
// on every such server both commands answered "command not found", as root
// too (docs/RECORD.md 4.220). The box's sudo is the distribution's own with
// its sudoers untouched, which is the whole of what is being tested.
func assertSudoFindsBothPrograms(t *testing.T, b *box, version string) {
	t.Helper()
	out, err := b.run("sudo", "whichports-agent", "--version")
	if err != nil {
		t.Errorf("`sudo whichports-agent` did not run, so the install command "+
			"stops at its enrol step on this family: %v\n%s", err, out)
	} else if !strings.Contains(out, "version="+version) {
		t.Errorf("`sudo whichports-agent --version` answered something else "+
			"than the installed %s:\n%s", version, out)
	}
	// --help prints one usage line and changes nothing, so it is safe to ask
	// in the middle of a run that still needs the agent installed.
	out, err = b.run("sudo", "whichports-uninstall", "--help")
	if err != nil {
		t.Errorf("`sudo whichports-uninstall` did not run, so the Remove "+
			"window's command fails on this family: %v\n%s", err, out)
	} else if !strings.Contains(out, "usage: whichports-uninstall") {
		t.Errorf("`sudo whichports-uninstall --help` did not print its usage:\n%s", out)
	}
}

// assertRepositoryConfigured is the answer to the fault docs/RECORD.md 4.48
// found on an old server of ours: a host reporting into production with no
// whichports apt source configured at all, so no publish could ever reach it.
// Two things have to hold. The source has to exist and be pinned to our key,
// and the package that landed has to have come through it.
func assertRepositoryConfigured(t *testing.T, b *box, f *fixture) {
	t.Helper()
	switch b.fam.name {
	case "ubuntu-26.04":
		b.mustExist("/etc/apt/sources.list.d/whichports.list",
			"the installer writes the apt source")
		source := b.mustRun("cat", "/etc/apt/sources.list.d/whichports.list")
		if !strings.Contains(source, "signed-by=/usr/share/keyrings/whichports.gpg") {
			t.Errorf("the apt source is not pinned to our keyring:\n%s", source)
		}
		b.mustExist("/usr/share/keyrings/whichports.gpg", "the installer writes the keyring")
		keyring := b.mustSh(
			`gpg --with-colons --show-keys /usr/share/keyrings/whichports.gpg`)
		if fpr := firstFingerprint(keyring); fpr != f.keyFPR {
			t.Errorf("the keyring on disk holds %q, want %q", fpr, f.keyFPR)
		}
		// apt's own account of where the installed version came from. The
		// whichports line has to be there and it has to be the one that won.
		policy := b.mustRun("apt-cache", "policy", "whichports-agent")
		if !strings.Contains(policy, "file:/repo/deb stable/main amd64 Packages") {
			t.Errorf("apt does not attribute the package to the whichports repository:\n%s", policy)
		}
		if !strings.Contains(policy, "Installed: "+oldVersion) {
			t.Errorf("apt reports a different installed version:\n%s", policy)
		}
	default:
		b.mustExist("/etc/yum.repos.d/whichports.repo",
			"the installer writes the dnf repository file")
		repo := b.mustRun("cat", "/etc/yum.repos.d/whichports.repo")
		for _, want := range []string{
			"gpgcheck=1",
			"repo_gpgcheck=1",
			"gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-whichports",
		} {
			if !strings.Contains(repo, want) {
				t.Errorf("the dnf repository file is missing %q:\n%s", want, repo)
			}
		}
		// gpgkey has to be a local file. With a URL there, dnf will fetch and
		// import whatever key that URL serves later, which would undo the
		// pinning the installer's fingerprint check just did.
		if strings.Contains(repo, "gpgkey=http") {
			t.Errorf("gpgkey points at a URL, so dnf could import a rotated key later:\n%s", repo)
		}
		b.mustExist("/etc/pki/rpm-gpg/RPM-GPG-KEY-whichports", "the installer writes the key")
		key := b.mustSh(`gpg --with-colons --show-keys /etc/pki/rpm-gpg/RPM-GPG-KEY-whichports`)
		if fpr := firstFingerprint(key); fpr != f.keyFPR {
			t.Errorf("the key on disk is %q, want %q", fpr, f.keyFPR)
		}
		from := strings.TrimSpace(b.mustRun("dnf", "repoquery", "--installed",
			"--qf", "%{from_repo}", "whichports-agent"))
		if from != "whichports" {
			t.Errorf("dnf says the package came from %q, want \"whichports\"", from)
		}
		// rpm records the signature it verified. An unsigned package would
		// leave this empty, which is the state the negative test provokes.
		sig := strings.TrimSpace(b.mustRun("rpm", "-q", "--qf", "%{SIGPGP:pgpsig}",
			"whichports-agent"))
		if sig == "" || strings.Contains(sig, "none") {
			t.Errorf("rpm holds no signature for the installed package, got %q", sig)
		}
		if !strings.Contains(strings.ToUpper(sig), strings.ToUpper(f.keyFPR[24:])) {
			t.Errorf("the package was signed by something other than the expected key.\n"+
				"  rpm says: %s\n  expected key id from: %s", sig, f.keyFPR)
		}
	}
}

// assertUnitsAfterInstall pins the promise the installer and the post-install
// scriptlet both make in words: the units are in place, systemd can see them,
// and nothing has been started. Turning on a recurring root job is the
// operator's decision, so an installer that enabled the timer would be breaking
// its own printed promise.
func assertUnitsAfterInstall(t *testing.T, b *box) {
	t.Helper()
	for _, unit := range []string{
		"/usr/lib/systemd/system/whichports-agent.service",
		"/usr/lib/systemd/system/whichports-agent.timer",
	} {
		b.mustExist(unit, "the package ships it")
	}
	// Visible to systemd, which is what the post-install daemon-reload buys.
	listed := b.mustRun("systemctl", "list-unit-files", "whichports-agent.service",
		"whichports-agent.timer")
	for _, unit := range []string{"whichports-agent.service", "whichports-agent.timer"} {
		if !strings.Contains(listed, unit) {
			t.Errorf("systemd cannot see %s after install:\n%s", unit, listed)
		}
	}
	// And loadable. A unit file with a typo in a directive installs perfectly
	// and fails only when something tries to start it.
	if out, err := b.run("systemd-analyze", "verify",
		"/usr/lib/systemd/system/whichports-agent.service"); err != nil {
		t.Errorf("systemd rejects the shipped service unit: %v\n%s", err, out)
	}
	if state := b.unitState("is-enabled", "whichports-agent.timer"); state != "disabled" {
		t.Errorf("the timer is %q after a fresh install, want disabled", state)
	}
	if state := b.unitState("is-active", "whichports-agent.timer"); state != "inactive" {
		t.Errorf("the timer is %q after a fresh install, want inactive", state)
	}
	if state := b.unitState("is-active", "whichports-agent.service"); state != "inactive" {
		t.Errorf("the service is %q after a fresh install, want inactive", state)
	}
	b.mustExist("/var/lib/whichports", "the post-install scriptlet creates the state directory")
	mode := strings.TrimSpace(b.mustRun("stat", "-c", "%a %U:%G", "/var/lib/whichports"))
	if mode != "750 whichports-agent:whichports-agent" {
		t.Errorf("the state directory is %q, want 750 whichports-agent:whichports-agent", mode)
	}
	// The dedicated user the unit runs as, created by the post-install
	// scriptlet. A system user with no login shell, because nothing ever logs
	// in as it.
	uid := strings.TrimSpace(b.mustRun("id", "-u", "whichports-agent"))
	if uid == "" || uid == "0" {
		t.Errorf("the whichports-agent user has uid %q, want a non-zero system uid", uid)
	}
	passwd := strings.TrimSpace(b.mustRun("getent", "passwd", "whichports-agent"))
	if !strings.HasSuffix(passwd, "/nologin") {
		t.Errorf("the whichports-agent user has a login shell:\n%s", passwd)
	}
}

// assertServiceIdentity reads who the service main process actually is, from
// the kernel rather than from the unit file. The unit file saying
// User=whichports-agent proves nothing about what systemd applied, and
// docs/RECORD.md 4.72 records two measurement runs that carried no
// capabilities at all while every file said they did. So the process reports
// on itself: a drop-in replaces ExecStart with one command that copies its
// own /proc/self/status into the state directory, and the user, the
// capabilities and the rest of the sandbox apply to that command exactly as
// they apply to the agent.
//
// The one exception is the exec-path restriction. The shipped unit marks the
// whole tree non-executable and lists only the agent binary as runnable, so a
// capture that runs /bin/sh could not start under it at all. This drop-in
// clears NoExecPaths and ExecPaths for the measurement, because this stage is
// about who the process is and not about the exec ban. That the exec ban
// itself refuses another program is proven on its own in
// TestCleanBoxRefusesExecUnderTheHardenedUnit.
func assertServiceIdentity(t *testing.T, b *box) {
	t.Helper()
	b.mustSh(`mkdir -p /etc/systemd/system/whichports-agent.service.d && ` +
		`printf '[Service]\nExecStart=\nExecStart=/bin/sh -c "cp /proc/self/status /var/lib/whichports/unit-identity"\nNoExecPaths=\nExecPaths=\n' ` +
		`> /etc/systemd/system/whichports-agent.service.d/identity-capture.conf && ` +
		`systemctl daemon-reload`)
	// The drop-in must not outlive this assertion, whichever way it ends: the
	// next stage starts the real service and has to get the real ExecStart.
	defer b.mustSh(`rm -rf /etc/systemd/system/whichports-agent.service.d && systemctl daemon-reload`)

	b.mustRun("systemctl", "start", "whichports-agent.service")
	status := b.mustRun("cat", "/var/lib/whichports/unit-identity")

	uid := statusField(status, "Uid")
	if uid == "" || strings.Fields(uid)[0] == "0" {
		t.Errorf("the service main process ran with Uid %q, want a non-zero uid. "+
			"Full status:\n%s", uid, status)
	}
	// CAP_NET_ADMIN is bit 12 and CAP_NET_RAW is bit 13, so exactly those two
	// is 0x3000. Exact match on purpose: one bit more is a capability the unit
	// was not supposed to keep, one bit less and a netlink read is quietly
	// failing somewhere.
	if capEff := statusField(status, "CapEff"); capEff != "0000000000003000" {
		t.Errorf("the service main process holds CapEff %q, want exactly "+
			"0000000000003000 (CAP_NET_ADMIN and CAP_NET_RAW). Full status:\n%s",
			capEff, status)
	}
}

// statusField pulls one field's value out of a /proc/<pid>/status dump.
func statusField(status, key string) string {
	for _, line := range strings.Split(status, "\n") {
		if rest, found := strings.CutPrefix(line, key+":"); found {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// assertCollectionUnderUnit runs the real service once, before enrollment,
// and holds the resulting document to what docs/RECORD.md 4.72 measured for
// a non-root user with the two network capabilities: the live kernel ruleset
// collects, and the ufw intent files are an honest permission_denied, because
// Ubuntu ships user.rules mode 640 root root and nothing has granted the
// agent user a read on it.
func assertCollectionUnderUnit(t *testing.T, b *box) {
	t.Helper()
	// Not enrolled yet, so a clean exit means the collection and the local
	// write both worked under the tightened unit, and nothing tried to leave.
	b.mustRun("systemctl", "start", "whichports-agent.service")

	mode := strings.TrimSpace(b.mustRun("stat", "-c", "%a %U:%G", "/var/lib/whichports/host.json"))
	if mode != "640 whichports-agent:whichports-agent" {
		t.Errorf("the host document is %q, want 640 whichports-agent:whichports-agent", mode)
	}

	raw := b.mustRun("cat", "/var/lib/whichports/host.json")
	var doc struct {
		Nftables *struct {
			Status string `json:"status"`
		} `json:"nftables"`
		Ufw *struct {
			Status  string `json:"status"`
			Sources map[string]struct {
				Status string `json:"status"`
			} `json:"sources"`
		} `json:"ufw"`
		Firewalld *struct {
			Status  string `json:"status"`
			Sources map[string]struct {
				Status string `json:"status"`
			} `json:"sources"`
		} `json:"firewalld"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("the host document does not parse: %v\n%s", err, raw)
	}
	// The published agent holds the package reader since 2026-10-12
	// (docs/SPEC-packages-switch.md), so its document has the packages key,
	// with a status on every box, also one that has no dpkg. Until then it
	// had no such key (docs/RECORD.md 4.369 and 4.385). The raw keys are
	// read, because an absent field and a null one decode alike.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		t.Fatalf("the host document does not parse: %v\n%s", err, raw)
	}
	if _, has := keys["packages"]; !has {
		t.Errorf("the installed agent's document carries no packages section")
	}
	if doc.Nftables == nil || doc.Nftables.Status != "collected" {
		t.Errorf("nftables did not collect under the non-root unit, and it must: "+
			"CAP_NET_ADMIN exists for exactly this read (docs/RECORD.md 4.72). Section: %+v",
			doc.Nftables)
	}
	// The declared side, read on the first collection through the installer's
	// read grants (record 4.176). The per-source verdicts, not the section
	// headline: the headline says collected as long as any world-readable file
	// was read, and that exact shape was wrong twice before 4.72 counted
	// the rules. Until 2026-09-13 this asserted permission_denied here, which
	// was the honest answer for a unit holding two capabilities and no grant.
	switch b.fam.name {
	case "ubuntu-26.04":
		if doc.Ufw == nil {
			t.Fatal("the document has no ufw section on Ubuntu with ufw installed")
		}
		for _, source := range []string{"user.rules", "user6.rules"} {
			if got := doc.Ufw.Sources[source].Status; got != "collected" {
				t.Errorf("ufw %s is %q, want collected: the file is 640 root:root and the "+
					"installer grants the agent user read on it", source, got)
			}
		}
	default:
		if doc.Firewalld == nil {
			t.Fatal("the document has no firewalld section on AlmaLinux with firewalld installed")
		}
		for _, source := range []string{"firewalld.conf", "etc_zones"} {
			if got := doc.Firewalld.Sources[source].Status; got != "collected" {
				t.Errorf("firewalld %s is %q, want collected: /etc/firewalld is 750 root:root "+
					"and the installer grants the agent user read and traverse on it", source, got)
			}
		}
	}
}

// assertReadGrants records the ACL entries the installer leaves, that a
// second run of the installer leaves exactly the same entries rather than a
// second copy, and that setfacl arrived with the package rather than being
// assumed on the box.
func assertReadGrants(t *testing.T, b *box) {
	t.Helper()
	b.mustSh("command -v setfacl")
	var files []string
	switch b.fam.name {
	case "ubuntu-26.04":
		files = []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"}
	default:
		files = []string{"/etc/firewalld", "/etc/firewalld/zones", "/etc/firewalld/firewalld.conf"}
	}
	count := func(path string) int {
		return strings.Count(b.mustRun("getfacl", "-p", path), "user:whichports-agent:")
	}
	for _, path := range files {
		acl := b.mustRun("getfacl", "-p", path)
		if !strings.Contains(acl, "user:whichports-agent:r") {
			t.Errorf("no read grant for the agent user on %s:\n%s", path, acl)
		}
		if strings.Contains(acl, "user:whichports-agent:rw") || strings.Contains(acl, "user:whichports-agent:-w") {
			t.Errorf("the grant on %s carries write, and the installer only ever grants read:\n%s", path, acl)
		}
	}
	b.mustInstall()
	for _, path := range files {
		if got := count(path); got != 1 {
			t.Errorf("after a second install %s carries %d entries for the agent user, want exactly one", path, got)
		}
	}
}

// assertUpgradeKeepsState is the regression test for the failure that cost this
// project two hours of a silent control plane. The old package's pre-remove runs
// during an upgrade in both families, and until 2026-08-15 it disabled the timer
// there, so every host that upgraded stopped reporting.
//
// The other half is enrolment. /etc/whichports/agent.conf is not owned by the
// package, which is why an upgrade does not disturb it. RECORD 4.48 says so.
// this proves it rather than repeating it.
func assertUpgradeKeepsState(t *testing.T, b *box, f *fixture, served string) {
	t.Helper()

	// The operator's two choices, made the way an operator makes them.
	b.mustRun("systemctl", "enable", "--now", "whichports-agent.timer")
	b.mustRun("mkdir", "-p", "/etc/whichports")
	b.mustSh(`printf 'server=https://app.example.invalid\ncredential=whp_cleanbox_marker\n' ` +
		`> /etc/whichports/agent.conf && chmod 600 /etc/whichports/agent.conf`)
	confBefore := b.mustRun("sha256sum", "/etc/whichports/agent.conf")

	if state := b.unitState("is-enabled", "whichports-agent.timer"); state != "enabled" {
		t.Fatalf("the timer did not enable, so the upgrade assertion would prove nothing (got %q)", state)
	}
	if state := b.unitState("is-active", "whichports-agent.timer"); state != "active" {
		t.Fatalf("the timer did not start, so the upgrade assertion would prove nothing (got %q)", state)
	}

	// A newer version appears in the repository the box is already configured
	// against, and the box upgrades itself the way an unattended host does.
	f.swap(t, served, f.repoBoth)
	var upgradeOutput string
	switch b.fam.name {
	case "ubuntu-26.04":
		// The same restricted update the installer uses, so no distribution
		// mirror is contacted. Then a plain upgrade, which is the command that
		// broke the fleet.
		b.mustRun("apt-get", "update",
			"-o", "Dir::Etc::sourcelist=sources.list.d/whichports.list",
			"-o", "Dir::Etc::sourceparts=-",
			"-o", "APT::Get::List-Cleanup=0")
		upgradeOutput = b.mustRun("apt-get", "upgrade", "-y")
	default:
		// --refresh because dnf caches repository metadata for hours and would
		// otherwise not notice the new version. --disablerepo keeps AlmaLinux's
		// own mirrors out of it, which is also how the upgrade was done on
		// one of our own servers when its disk was full (RECORD 4.48).
		upgradeOutput = b.mustRun("dnf", "-y", "--refresh", "--disablerepo=*",
			"--enablerepo=whichports", "upgrade", "whichports-agent")
	}

	// What the operator is told, on a box that is already enrolled and whose
	// timer is already on. Both instructions the banner used to print
	// unconditionally are things this host did months ago, and printing them
	// under a package it did not choose to be told about is noise that hides
	// the lines that matter (the owner, 2026-08-22, reading a fleet upgrade).
	//
	// This is the only place the enrolled branch can be asserted: the script
	// reads /etc/whichports/agent.conf by absolute path, and this box has a
	// real one, written above.
	if strings.Contains(upgradeOutput, "whichports-agent enroll") {
		t.Errorf("the upgrade told an already enrolled host to enrol:\n%s", upgradeOutput)
	}
	if !strings.Contains(upgradeOutput, "enrolled already") {
		t.Errorf("the upgrade said nothing about the enrolment it found:\n%s", upgradeOutput)
	}
	if strings.Contains(upgradeOutput, "systemctl enable --now") {
		t.Errorf("the upgrade told an operator to enable a timer that is on:\n%s", upgradeOutput)
	}

	if v := b.installedVersion(); v != newVersion {
		t.Fatalf("the upgrade did not happen: version is %q, want %q", v, newVersion)
	}
	// The binary on disk has to have moved too, and the package manager's record
	// cannot tell you that. This is the check that catches an upgrade that
	// updates the record and leaves the old executable in place, which is the
	// fault 4.48 found in a different form and which nothing here could see
	// before the agent could be asked what it is.
	after := strings.Fields(b.mustRun("sha256sum", "/usr/bin/whichports-agent"))
	if len(after) == 0 || after[0] != f.newBinarySHA {
		t.Errorf("the upgrade did not replace the binary.\n  on the box:   %v\n"+
			"  9.9.9 build: %s\n  9.9.8 build: %s", after, f.newBinarySHA, f.binarySHA)
	}
	if out, err := b.run("/usr/bin/whichports-agent", "--version"); err != nil {
		t.Errorf("the upgraded agent could not be asked what it is: %v\n%s", err, out)
	} else if line := strings.TrimSpace(out); !strings.Contains(line, "version="+newVersion) {
		t.Errorf("the upgraded binary still calls itself the old version.\n"+
			"  binary:  %s\n  package: %s", line, newVersion)
	}
	if state := b.unitState("is-enabled", "whichports-agent.timer"); state != "enabled" {
		t.Errorf("the upgrade disabled the timer (%q). This is docs/RECORD.md 4.48 "+
			"happening again: every host that upgrades goes silent.", state)
	}
	if state := b.unitState("is-active", "whichports-agent.timer"); state != "active" {
		t.Errorf("the upgrade stopped the timer (%q). This is docs/RECORD.md 4.48 "+
			"happening again: every host that upgrades goes silent.", state)
	}
	if after := b.mustRun("sha256sum", "/etc/whichports/agent.conf"); after != confBefore {
		t.Errorf("the upgrade changed the enrolment file.\n  before: %s  after:  %s",
			confBefore, after)
	}
	// The content survives untouched, and the ownership does not: the conf
	// above was written the way a root-era install left it, root:root 0600,
	// which the non-root agent cannot read. The new package's post-install is
	// the only thing that can fix a file no package owns, so this asserts it
	// did (docs/RECORD.md 4.72 is the measurement behind the 640 shape).
	confMode := strings.TrimSpace(b.mustRun("stat", "-c", "%a %U:%G", "/etc/whichports/agent.conf"))
	if confMode != "640 root:whichports-agent" {
		t.Errorf("after the upgrade the enrolment file is %q, want 640 root:whichports-agent, "+
			"so a root-era install keeps reporting once the agent stops being root", confMode)
	}
	// A fresh enrolment on the upgraded host has to come out the same shape
	// without waiting for the next upgrade to fix it. whp_ plus 32 word
	// characters is the credential shape the agent accepts.
	b.mustRun("/usr/bin/whichports-agent", "enroll",
		"--server=https://app.example.invalid",
		"--credential=whp_cleanbox0123456789abcdefghijklmnop")
	confMode = strings.TrimSpace(b.mustRun("stat", "-c", "%a %U:%G", "/etc/whichports/agent.conf"))
	if confMode != "640 root:whichports-agent" {
		t.Errorf("a fresh enrolment wrote the config as %q, want 640 root:whichports-agent", confMode)
	}
	assertEnrolUnderAHardenedUmask(t, b)
	// And the reason it survives: no package owns it.
	switch b.fam.name {
	case "ubuntu-26.04":
		out := b.mustFail("the enrolment file must not be owned by the package",
			"dpkg", "-S", "/etc/whichports/agent.conf")
		if !strings.Contains(out, "no path found") {
			t.Errorf("unexpected dpkg answer for the enrolment file:\n%s", out)
		}
	default:
		out := b.mustFail("the enrolment file must not be owned by the package",
			"rpm", "-qf", "/etc/whichports/agent.conf")
		if !strings.Contains(out, "not owned by any package") {
			t.Errorf("unexpected rpm answer for the enrolment file:\n%s", out)
		}
	}
}

// assertEnrolUnderAHardenedUmask is the first install on someone else's server
// (docs/RECORD.md 4.201), replayed. The admins there run a strict umask, enroll
// created /etc/whichports 0700 root:root under it, and the unit's user could
// not reach the 0640 file inside, so every run failed with "read config: stat
// /etc/whichports/agent.conf: permission denied" and nothing was ever sent.
//
// It runs the real unit rather than checking modes alone, because the modes
// were right by every check this harness made and the host still failed. The
// box is enrolled against an address that cannot resolve, so the run fails
// at delivery either way. What matters is that it got that far: a config the
// unit cannot reach fails before any network is tried.
func assertEnrolUnderAHardenedUmask(t *testing.T, b *box) {
	t.Helper()
	b.mustSh("rm -rf /etc/whichports && umask 077 && /usr/bin/whichports-agent enroll" +
		" --server=https://app.example.invalid --credential=whp_cleanbox0123456789abcdefghijklmnop")
	if got := strings.TrimSpace(b.mustRun("stat", "-c", "%a %U:%G", "/etc/whichports")); got != "711 root:root" {
		t.Errorf("enrolled under umask 077, /etc/whichports is %q, want 711 root:root, "+
			"so the agent's user can search it", got)
	}

	since := strings.TrimSpace(b.mustRun("date", "+%s"))
	// Fails at delivery, and a failed oneshot fails systemctl start, so the
	// error is expected and the journal is the evidence.
	b.run("systemctl", "start", "whichports-agent.service")
	// journald takes the unit's output off a stream, so the lines can land a
	// moment after systemctl returns. Wait up to five seconds for either one.
	journal := b.mustSh("for i in $(seq 50); do" +
		" out=$(journalctl -q -u whichports-agent.service --since=@" + since + " -o cat --no-pager);" +
		" case \"$out\" in *'read config'*|*'deliver report'*) break ;; esac; sleep 0.1; done;" +
		" printf '%s\\n' \"$out\"")
	if strings.Contains(journal, "read config") {
		t.Errorf("the unit could not read the config enrolled under umask 077:\n%s", journal)
	}
	if !strings.Contains(journal, "deliver report") {
		t.Errorf("the unit never reached delivery after an enrolment under umask 077:\n%s", journal)
	}
}

// assertRemoval records exactly what a removal takes away and exactly what it
// leaves. The leftovers are not all accidents: the post-remove scriptlet says in
// its own comment that the state directory is the operator's data and stays. The
// repository configuration and the enrolment file stay too, and neither is the
// package manager's to remove, because the installer script put them there and
// no package owns them.
func assertRemoval(t *testing.T, b *box) {
	t.Helper()
	switch b.fam.name {
	case "ubuntu-26.04":
		b.mustRun("apt-get", "remove", "-y", "whichports-agent")
	default:
		b.mustRun("dnf", "-y", "remove", "whichports-agent")
	}

	b.mustNotExist("/usr/bin/whichports-agent", "the package was removed")
	b.mustNotExist("/usr/lib/systemd/system/whichports-agent.service", "the package was removed")
	b.mustNotExist("/usr/lib/systemd/system/whichports-agent.timer", "the package was removed")
	// The pre-remove tears the timer down on a real removal, so no enablement
	// symlink may be left pointing at a unit file that no longer exists.
	b.mustNotExist("/etc/systemd/system/timers.target.wants/whichports-agent.timer",
		"the pre-remove scriptlet disables the timer on a real removal")
	if state := b.unitState("is-enabled", "whichports-agent.timer"); state != "not-found" {
		t.Errorf("systemd still knows the timer as %q after removal", state)
	}

	// What survives a removal, stated rather than assumed.
	b.mustExist("/var/lib/whichports", "the post-remove scriptlet leaves the operator's data")
	b.mustExist("/etc/whichports/agent.conf", "no package owns the enrolment file")
	// The system user stays too, on purpose: it still owns the state directory
	// left above, and deleting a uid that files still carry would let a future
	// unrelated user inherit them.
	b.mustRun("getent", "passwd", "whichports-agent")

	switch b.fam.name {
	case "ubuntu-26.04":
		// dpkg keeps the package name in `deinstall ok config-files` after a
		// plain remove. That is the exact state RECORD 4.48 found on the old
		// VPS, and it is ordinary rather than broken: it means somebody ran
		// remove and not purge.
		state := strings.TrimSpace(b.mustRun("dpkg-query", "-W", "-f=${Status}",
			"whichports-agent"))
		if state != "deinstall ok config-files" {
			t.Errorf("dpkg state after remove is %q, want \"deinstall ok config-files\"", state)
		}
		b.mustRun("apt-get", "purge", "-y", "whichports-agent")
		if out, err := b.run("dpkg-query", "-W", "whichports-agent"); err == nil {
			t.Errorf("dpkg still knows the package after a purge:\n%s", out)
		}
	default:
		if out, err := b.run("rpm", "-q", "whichports-agent"); err == nil {
			t.Errorf("rpm still knows the package after removal:\n%s", out)
		}
	}

	// A purge is cleaner only in the package manager's own records. Everything
	// the installer script put on the box outlives it, including a credential.
	// This is asserted rather than wished for, so that changing it is a
	// deliberate act with a failing test to prompt it.
	b.mustExist("/etc/whichports/agent.conf",
		"nothing in the removal path touches the enrolment file, credential included")
	switch b.fam.name {
	case "ubuntu-26.04":
		b.mustExist("/etc/apt/sources.list.d/whichports.list",
			"the installer wrote the apt source and no package owns it")
		b.mustExist("/usr/share/keyrings/whichports.gpg",
			"the installer wrote the keyring and no package owns it")
	default:
		b.mustExist("/etc/yum.repos.d/whichports.repo",
			"the installer wrote the dnf repository file and no package owns it")
		b.mustExist("/etc/pki/rpm-gpg/RPM-GPG-KEY-whichports",
			"the installer wrote the key file and no package owns it")
	}
}

// TestCleanBoxUpgradeLeavesADisabledTimerDisabled is the other side of the 4.48
// fix. The pre-remove now leaves the operator's choice alone on an upgrade, and
// "alone" has to mean off as well as on. An upgrade that quietly enabled a timer
// the operator had deliberately left off would be the same broken promise in the
// other direction.
func TestCleanBoxUpgradeLeavesADisabledTimerDisabled(t *testing.T) {
	f := requireFixture(t)
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			served := f.serve(t, f.repoOld)
			b := startBox(t, fam, fam.image, served)
			b.mustInstall()
			if state := b.unitState("is-enabled", "whichports-agent.timer"); state != "disabled" {
				t.Fatalf("timer is %q before the upgrade, want disabled", state)
			}

			f.swap(t, served, f.repoBoth)
			switch fam.name {
			case "ubuntu-26.04":
				b.mustRun("apt-get", "update",
					"-o", "Dir::Etc::sourcelist=sources.list.d/whichports.list",
					"-o", "Dir::Etc::sourceparts=-",
					"-o", "APT::Get::List-Cleanup=0")
				b.mustRun("apt-get", "upgrade", "-y")
			default:
				b.mustRun("dnf", "-y", "--refresh", "--disablerepo=*",
					"--enablerepo=whichports", "upgrade", "whichports-agent")
			}

			if v := b.installedVersion(); v != newVersion {
				t.Fatalf("the upgrade did not happen: version is %q, want %q", v, newVersion)
			}
			if state := b.unitState("is-enabled", "whichports-agent.timer"); state != "disabled" {
				t.Errorf("the upgrade enabled a timer the operator had left off (%q)", state)
			}
			if state := b.unitState("is-active", "whichports-agent.timer"); state != "inactive" {
				t.Errorf("the upgrade started a timer the operator had left off (%q)", state)
			}
		})
	}
}

// TestCleanBoxRefusesExecUnderTheHardenedUnit puts the exec backstop on real
// systemd. The shipped unit adds NoExecPaths=/ with a single ExecPaths entry
// for the agent, and this is where the claim that they refuse another program
// is measured instead of asserted.
//
// The reason a runtime backstop exists rather than a list entry is that the
// source scan in agent/internal/safety can name the exec wrappers but cannot
// see a raw unix.Syscall6, and the agent already makes one of those for the
// x_tables getsockopt. A Syscall6 aimed at execve would pass the scan. A
// noexec mount does not care which call asked, so it closes that gap.
//
// The companion half, that the agent's own static binary still starts and
// collects a whole document under the same NoExecPaths=/ sandbox, is stage 6
// of TestCleanBoxInstall. Between the two, the tightening is shown to stop the
// thing it targets without stopping the thing it protects.
//
// /usr/bin/true is the probe on purpose. A program that always exits 0 can
// only make "systemctl start" fail if the exec itself never happened, so a
// failed start here is unambiguous. The second case is the control: it runs
// the very same command with NoExecPaths and ExecPaths cleared and it must
// succeed. Without that half the first case would prove nothing, because a
// start can fail for any number of reasons and this pins the reason to the one
// directive.
func TestCleanBoxRefusesExecUnderTheHardenedUnit(t *testing.T) {
	f := requireFixture(t)
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			served := f.serve(t, f.repoOld)
			b := startBox(t, fam, fam.image, served)
			b.mustInstall()

			// The probe has to exist, or its absence would read exactly like the
			// exec being refused. /usr/bin/true is coreutils on both families.
			b.mustExist("/usr/bin/true", "coreutils ships it on both families")

			// setProbe points ExecStart at /usr/bin/true, plus whatever extra unit
			// lines the case needs. clearProbe removes it, so the two cases cannot
			// bleed into each other and the box is left with the real ExecStart.
			setProbe := func(extra string) {
				b.mustSh(`mkdir -p /etc/systemd/system/whichports-agent.service.d && ` +
					`printf '[Service]\nExecStart=\nExecStart=/usr/bin/true\n` + extra + `' ` +
					`> /etc/systemd/system/whichports-agent.service.d/exec-probe.conf && ` +
					`systemctl daemon-reload`)
			}
			clearProbe := func() {
				b.mustSh(`rm -f /etc/systemd/system/whichports-agent.service.d/exec-probe.conf && ` +
					`systemctl daemon-reload`)
			}

			// Refused: the unit exactly as shipped. NoExecPaths=/ is inherited and
			// /usr/bin/true is not the one binary ExecPaths allows, so the kernel
			// refuses to execute it and the oneshot start fails.
			setProbe(``)
			out := b.mustFail(
				"NoExecPaths=/ must stop systemd executing a program that is not the agent",
				"systemctl", "start", "whichports-agent.service")
			// 203 is systemd's EXIT_EXEC, the status it records when execve itself
			// failed, which for a binary that exists and is 0755 is the noexec
			// mount refusing it. Pinning it separates this refusal from an
			// unrelated start failure, which would fail mustFail for the wrong
			// reason and quietly stop testing the backstop.
			status := b.mustRun("systemctl", "show", "whichports-agent.service",
				"-p", "ExecMainStatus", "-p", "Result", "-p", "ActiveState")
			if !strings.Contains(status, "ExecMainStatus=203") {
				t.Errorf("the start was refused, but not with EXIT_EXEC (203), so it may "+
					"have failed for a reason other than the exec being blocked.\n"+
					"systemctl start said:\n%s\nsystemctl show said:\n%s", out, status)
			}
			clearProbe()

			// Allowed: the identical command with the exec-path restriction cleared.
			// It has to succeed. /usr/bin/true exiting 0 is what a clean start looks
			// like, and it is the difference between this case and the one above
			// that names NoExecPaths as the thing doing the refusing.
			setProbe(`NoExecPaths=\nExecPaths=\n`)
			b.mustRun("systemctl", "start", "whichports-agent.service")
			clearProbe()
		})
	}
}

// TestCleanBoxRefusesAWrongSigningKey breaks the fingerprint pin on purpose. The
// installer is asked to trust a site that serves a key it did not publish, and
// it has to stop before touching anything.
func TestCleanBoxRefusesAWrongSigningKey(t *testing.T) {
	f := requireFixture(t)
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			served := f.serve(t, f.repoOld)
			b := startBox(t, fam, fam.image, served)

			// Put the pinned fingerprint of the real published key back into the
			// served script while the site keeps serving the throwaway key. Now
			// the two disagree, which is what a swapped key looks like.
			b.mustSh("sed 's|^KEY_FPR=.*$|" + publishedFPRLine + "|' /repo/install.sh > /tmp/pinned.sh")
			pinned, err := b.run("grep", "-c", "-F", publishedFPRLine, "/tmp/pinned.sh")
			if err != nil || strings.TrimSpace(pinned) != "1" {
				t.Fatalf("the pinned fingerprint was not put back into the script "+
					"(grep -c said %q, err %v), so this test would have proved nothing",
					strings.TrimSpace(pinned), err)
			}

			out := b.mustFail("a served key that does not match the pin must stop the install",
				"sh", "/tmp/pinned.sh")
			if !strings.Contains(out, "signing key fingerprint mismatch") {
				t.Errorf("the installer refused for the wrong reason:\n%s", out)
			}
			assertNothingInstalled(t, b)
		})
	}
}

// TestCleanBoxRefusesATamperedRepository takes the repository signature away in
// the two ways it can go wrong, and requires a refusal for each.
//
// This is the check that still stands after the key is on disk. The installer's
// fingerprint pin only guards the moment the key arrives. From then on it is the
// package manager verifying the repository against that key, every single time,
// and that is the property being asserted here.
//
// The two families are protected differently and the test says so rather than
// pretending they are the same. apt verifies the InRelease signature and then
// trusts the hashes inside it, and it does not look at a .deb's own signature at
// all, so on the Debian side the repository signature is the whole protection.
// dnf verifies the metadata signature and every package's signature separately,
// which is why there is an extra test below for the package half.
func TestCleanBoxRefusesATamperedRepository(t *testing.T) {
	f := requireFixture(t)
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			t.Run("signed_by_another_key", func(t *testing.T) {
				served := f.serve(t, f.repoOld)
				f.signWithImpostor(t, served, fam)
				b := startBox(t, fam, fam.image, served)
				out, err := b.install()
				if err == nil {
					t.Fatalf("the install went through against a repository signed by a "+
						"key this box has never trusted:\n%s", out)
				}
				assertNothingInstalled(t, b)
			})
			t.Run("signature_removed", func(t *testing.T) {
				served := f.serve(t, f.repoOld)
				removeSignatures(t, served, fam)
				b := startBox(t, fam, fam.image, served)
				out, err := b.install()
				if err == nil {
					t.Fatalf("the install went through against an unsigned repository:\n%s", out)
				}
				assertNothingInstalled(t, b)
			})
		})
	}
}

// TestCleanBoxRefusesAnUnsignedPackage is the RHEL half of "the package it
// installs is the signed one rather than something built locally". The
// repository metadata is signed correctly and the package inside it is not
// signed at all, which is what a locally built package dropped into a real
// repository looks like. dnf's gpgcheck has to refuse it.
//
// There is no Debian counterpart and that is a real difference rather than an
// omission: apt does not verify a .deb's own signature, so on the Debian side
// the only thing standing between an operator and a swapped package is the
// InRelease signature, which the tampered-repository test above covers.
func TestCleanBoxRefusesAnUnsignedPackage(t *testing.T) {
	f := requireFixture(t)
	fam := families[1]
	if fam.name != "almalinux-10" {
		t.Fatalf("expected the second family to be almalinux, got %q", fam.name)
	}
	served := f.serve(t, f.repoUnsigned)
	b := startBox(t, fam, fam.image, served)

	out, err := b.install()
	if err == nil {
		t.Fatalf("dnf installed a package with no signature:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "not signed") &&
		!strings.Contains(strings.ToLower(out), "gpg check") &&
		!strings.Contains(strings.ToLower(out), "signature") {
		t.Errorf("dnf refused for a reason that does not look like a signature check:\n%s", out)
	}
	assertNothingInstalled(t, b)
}

// TestCleanBoxRefusesWithoutGPG runs the installer on the untouched
// distribution images. Neither ships gpg, and ubuntu:26.04 does not ship curl
// either, so the published one-liner cannot run there at all. The installer's
// job in that case is to say what is missing and install nothing.
func TestCleanBoxRefusesWithoutGPG(t *testing.T) {
	f := requireFixture(t)
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			served := f.serve(t, f.repoOld)
			// No systemd in these images, so the box is started with a command
			// that simply waits, and only the installer's refusal is asserted.
			b := startBare(t, fam, served)

			if _, err := b.run("sh", "-c", "command -v gpg"); err == nil {
				t.Skipf("%s now ships gpg, so this case no longer exists", fam.baseImage)
			}
			out, err := b.run("sh", "/repo/install.sh")
			if err == nil {
				t.Fatalf("the installer ran without gpg:\n%s", out)
			}
			if !strings.Contains(out, "gpg not found") {
				t.Errorf("the installer refused without naming the missing tool:\n%s", out)
			}
			assertNothingInstalled(t, b)
		})
	}
}

// TestCleanBoxRefusesANonRootUser checks the first line of the installer's own
// preflight. It matters because the page tells people to pipe it into sh, and a
// script that got halfway through as a normal user would leave a half-configured
// package manager behind.
func TestCleanBoxRefusesANonRootUser(t *testing.T) {
	f := requireFixture(t)
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			served := f.serve(t, f.repoOld)
			b := startBox(t, fam, fam.image, served)

			// 65534 is nobody on both families.
			out, err := dockerOutput("exec", "--user", "65534", b.name,
				"sh", "-c", "curl -fsSL file:///repo/install.sh | sh")
			if err == nil {
				t.Fatalf("the installer ran as an unprivileged user:\n%s", out)
			}
			if !strings.Contains(out, "run as root") {
				t.Errorf("the installer refused without saying why:\n%s", out)
			}
			assertNothingInstalled(t, b)
		})
	}
}

// TestCleanBoxInstallsOverFirewalldsPackagedLink is stock Fedora 44 with
// firewalld, rebuilt on the RHEL-family box. firewalld-2.4.4-1.fc44 ships
// /etc/firewalld/firewalld.conf as a link to firewalld-standard.conf beside
// it, and until 0.1.12 the installer refused every link and stopped before
// the customer's enrol step could run (docs/RECORD.md 4.223). AlmaLinux ships
// a plain file, so the box is put into Fedora's shape by hand first.
//
// The box has to end the way any install ends: the installer finishes, the
// grant sits on the file that holds the configuration, and the agent's own
// user reads it through the link.
func TestCleanBoxInstallsOverFirewalldsPackagedLink(t *testing.T) {
	f := requireFixture(t)
	for _, fam := range families {
		if fam.name != "almalinux-10" {
			// ufw's files are plain files and the Ubuntu box has no firewalld.
			continue
		}
		t.Run(fam.name, func(t *testing.T) {
			served := f.serve(t, f.repoOld)
			b := startBox(t, fam, fam.image, served)
			b.mustSh("cd /etc/firewalld && mv firewalld.conf firewalld-standard.conf" +
				" && ln -s firewalld-standard.conf firewalld.conf")

			out := b.mustInstall()
			if !strings.Contains(out, "installed. Next steps:") {
				t.Errorf("the installer did not reach its closing lines over "+
					"firewalld's packaged link:\n%s", out)
			}
			acl := b.mustRun("getfacl", "-p", "/etc/firewalld/firewalld-standard.conf")
			if !strings.Contains(acl, "user:whichports-agent:r--") {
				t.Errorf("the file the link resolves to carries no read grant "+
					"for the agent user:\n%s", acl)
			}
			if link := strings.TrimSpace(b.mustRun("readlink", "/etc/firewalld/firewalld.conf")); link != "firewalld-standard.conf" {
				t.Errorf("the installer changed firewalld's link, it now reads %q", link)
			}
			// The reason for the grant, asked the way the unit asks it.
			b.mustRun("sudo", "-u", "whichports-agent", "head", "-n", "1", "/etc/firewalld/firewalld.conf")

			// And the uninstaller takes the grant back through the same link.
			b.mustRun("whichports-uninstall", "--yes")
			// dnf takes acl away with the agent, so getfacl is put back to
			// read with, for the reason the uninstaller's own test gives.
			if _, err := b.run("sh", "-c", "command -v getfacl"); err != nil {
				b.mustRun("dnf", "install", "-y", "acl")
			}
			acl = b.mustRun("getfacl", "-p", "/etc/firewalld/firewalld-standard.conf")
			if strings.Contains(acl, "whichports-agent") {
				t.Errorf("after the uninstaller the file still carries an entry "+
					"for the agent user:\n%s", acl)
			}
		})
	}
}

// assertNothingInstalled is the second half of every negative test. A refusal
// that still left a repository configured or a binary on disk would be worse
// than no refusal, because the operator would believe nothing happened.
func assertNothingInstalled(t *testing.T, b *box) {
	t.Helper()
	b.mustNotExist("/usr/bin/whichports-agent", "the install was refused")
	b.mustNotExist("/usr/lib/systemd/system/whichports-agent.timer", "the install was refused")
	b.mustNotExist("/var/lib/whichports", "the install was refused")
}

// TestCleanBoxUninstallerLeavesOnlyTheAccount runs the shipped uninstaller on
// a box the installer set up, with the installer's read grants on it and the
// drop-in an installer before 0.1.10 used to write, and records
// exactly what it takes and exactly what it leaves. The owner, 2026-09-12: fully
// off the machine has to be true rather than nearly true.
//
// What it leaves is the system user and group, and that is the one leftover
// with a reason: Debian's guidance for maintainer scripts says to leave the
// account so the id is never reused while files or backups still carry it
// (docs/PRODUCT.md 4f). The uninstaller says so in its closing lines, and this
// test holds it to that sentence, because a "Removed." with nothing after it
// would imply the opposite.
func TestCleanBoxUninstallerLeavesOnlyTheAccount(t *testing.T) {
	f := requireFixture(t)
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			served := f.serve(t, f.repoOld)
			b := startBox(t, fam, fam.image, served)
			b.mustInstall()
			b.mustRun("systemctl", "enable", "--now", "whichports-agent.timer")
			// An enrolment file, as `whichports-agent enroll` leaves it: not
			// owned by the package, and the thing the uninstaller exists for.
			b.mustSh("mkdir -p /etc/whichports && printf 'placeholder\\n' > /etc/whichports/agent.conf" +
				" && chown root:whichports-agent /etc/whichports/agent.conf && chmod 0640 /etc/whichports/agent.conf")
			// The installer applied the read grants; the drop-in is what an
			// installer before 0.1.10 could write.
			b.mustSh("mkdir -p /etc/systemd/system/whichports-agent.service.d" +
				" && printf '[Service]\\n' > /etc/systemd/system/whichports-agent.service.d/full-visibility.conf" +
				" && systemctl daemon-reload")

			out := b.mustRun("whichports-uninstall", "--yes")
			for _, want := range []string{
				"Removed. This host no longer reports.",
				"system user and group whichports-agent",
				"not the same as revoked",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("the uninstaller never said %q. Full output:\n%s", want, out)
				}
			}

			// Gone: everything the installer, the package and the operator's
			// grants put on the box.
			for path, why := range map[string]string{
				"/usr/bin/whichports-agent":                                      "the package was purged",
				"/usr/bin/whichports-uninstall":                                  "the package was purged, script included",
				"/usr/lib/systemd/system/whichports-agent.service":               "the package was purged",
				"/usr/lib/systemd/system/whichports-agent.timer":                 "the package was purged",
				"/etc/systemd/system/timers.target.wants/whichports-agent.timer": "the timer was disabled",
				"/etc/whichports":     "the enrolment directory is removed by exact path",
				"/var/lib/whichports": "the state directory is removed by exact path",
				"/etc/systemd/system/whichports-agent.service.d/full-visibility.conf": "the pre-0.1.10 drop-in is taken back",
				"/etc/apt/sources.list.d/whichports.list":                             "the installer's apt source is removed",
				"/usr/share/keyrings/whichports.gpg":                                  "the installer's keyring is removed",
				"/etc/apt/apt.conf.d/51whichports":                                    "the unattended-upgrades allowance is removed",
				"/etc/yum.repos.d/whichports.repo":                                    "the installer's dnf repo is removed",
				"/etc/pki/rpm-gpg/RPM-GPG-KEY-whichports":                             "the installer's rpm key is removed",
			} {
				b.mustNotExist(path, why)
			}
			for _, path := range []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules",
				"/etc/firewalld", "/etc/firewalld/zones", "/etc/firewalld/firewalld.conf"} {
				if !b.exists(path) {
					continue
				}
				// dnf takes acl away with the agent when the agent's install is
				// what brought it: AlmaLinux 10's /etc/dnf/dnf.conf sets
				// clean_requirements_on_remove=True. An ACL entry lives on the
				// file and stays whether the tools do or not, so the tools are
				// installed again here, only to read. ls cannot stand in: it
				// marks any ACL with a +, and setfacl -x leaves a mask:: entry
				// behind when it takes a named entry away, so a correct
				// uninstall still shows + (measured in both boxes, 2026-09-29).
				// The box already reaches its distribution's mirrors, which is
				// where the install got acl in the first place.
				if _, err := b.run("sh", "-c", "command -v getfacl"); err != nil {
					b.mustRun("dnf", "install", "-y", "acl")
				}
				acl := b.mustRun("getfacl", "-p", path)
				if strings.Contains(acl, "user:whichports-agent:") {
					t.Errorf("the agent's ACL entry on %s outlived the uninstaller:\n%s", path, acl)
				}
			}
			if state := b.unitState("is-enabled", "whichports-agent.timer"); state != "not-found" {
				t.Errorf("systemd still knows the timer as %q after the uninstaller", state)
			}
			switch fam.name {
			case "ubuntu-26.04":
				if out, err := b.run("dpkg-query", "-W", "whichports-agent"); err == nil {
					t.Errorf("dpkg still knows the package after the uninstaller:\n%s", out)
				}
			default:
				if out, err := b.run("rpm", "-q", "whichports-agent"); err == nil {
					t.Errorf("rpm still knows the package after the uninstaller:\n%s", out)
				}
			}

			// Left, and said so: the account, locked, with no shell.
			passwd := strings.TrimSpace(b.mustRun("getent", "passwd", "whichports-agent"))
			if !strings.HasSuffix(passwd, "nologin") {
				t.Errorf("the account that stays must be a locked one:\n%s", passwd)
			}
			b.mustRun("getent", "group", "whichports-agent")
			// And nothing on the disk still carries the id, so the two lines
			// the uninstaller prints for removing it would be safe to run.
			if owned := strings.TrimSpace(b.mustSh(
				"find / -xdev \\( -user whichports-agent -o -group whichports-agent \\) 2>/dev/null")); owned != "" {
				t.Errorf("files still carry the agent's uid or gid after the uninstaller:\n%s", owned)
			}
		})
	}
}

// TestCleanBoxRefusesAnUnknownInstallerFlag pins the argument parser. The
// installer takes no arguments since 0.1.10, and one that silently ignored
// an argument would install while the operator believed they had asked for
// something else, with nothing on the host saying otherwise. The argument
// used is the flag that existed until 0.1.10, misspelled as it once was in
// this test, so both the retired flag and a typo of it are covered.
func TestCleanBoxRefusesAnUnknownInstallerFlag(t *testing.T) {
	f := requireFixture(t)
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			served := f.serve(t, f.repoOld)
			b := startBox(t, fam, fam.image, served)

			out, err := b.sh("curl -fsSL file:///repo/install.sh | sh -s -- --full-visibilty")
			if err == nil {
				t.Fatalf("the installer accepted a misspelled flag on %s:\n%s", fam.name, out)
			}
			assertNothingInstalled(t, b)

			// The same for a credential copied wrongly: refused for its shape
			// before anything is fetched, where until 0.1.12 the package was
			// installed first and the enrolment refused after it
			// (docs/RECORD.md 4.251).
			out, err = b.sh("curl -fsSL file:///repo/install.sh | sh -s -- enroll" +
				" --server=https://app.example.invalid --credential=hello")
			if err == nil {
				t.Fatalf("the installer accepted a credential of the wrong shape on %s:\n%s", fam.name, out)
			}
			if !strings.Contains(out, "the credential is not one the dashboard hands out") {
				t.Errorf("the refusal does not say it is the credential:\n%s", out)
			}
			assertNothingInstalled(t, b)
			b.mustNotExist("/etc/whichports/agent.conf", "a refused credential enrolled the server")
		})
	}
}

// The command the Add server window hands out, on a clean box: one pipe, with
// the enrolment as the installer's arguments.
//
//	curl -fsSL .../install.sh | sudo sh -s -- enroll --server=... --credential=...
//
// Until 0.1.12 the window chained the enrolment after the pipe with &&, and a
// failed download carried on to "sudo: whichports-agent: command not found",
// because a pipe's exit status is the shell's and a shell given nothing exits
// 0 (docs/RECORD.md 4.228). The packaging tests run the script against stubs.
// This is the same three cases with a real package manager and a real init.
const enrolArguments = "enroll --server=https://app.example.invalid" +
	" --credential=whp_cleanbox0123456789abcdefghijklmnop"

// TestCleanBoxInstallerConnectsTheServerWhenAskedTo is the whole of what the
// window's command does. The server named cannot resolve, so the first
// collection fails at delivery and the installer has to say so and exit 1,
// with everything before that step done: installed, enrolled, timer on.
func TestCleanBoxInstallerConnectsTheServerWhenAskedTo(t *testing.T) {
	f := requireFixture(t)
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			served := f.serve(t, f.repoOld)
			b := startBox(t, fam, fam.image, served)

			since := strings.TrimSpace(b.mustRun("date", "+%s"))
			// Through sudo, as the window writes it, so the installer's call
			// to the agent runs under sudo's own PATH.
			out, err := b.sh("curl -fsSL file:///repo/install.sh | sudo sh -s -- " + enrolArguments)
			if err == nil {
				t.Errorf("the installer exited 0 although the first report could "+
					"not be delivered to a name that does not resolve:\n%s", out)
			}
			for _, want := range []string{
				"installing whichports-agent",
				"connecting this server",
				"enrolled: reports will be delivered to https://app.example.invalid",
				"the first report did not go out",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("the installer never said %q. Full output:\n%s", want, out)
				}
			}
			if strings.Contains(out, "command not found") {
				t.Errorf("the installer could not find the agent under sudo:\n%s", out)
			}

			conf := strings.TrimSpace(b.mustRun("stat", "-c", "%a %U:%G", "/etc/whichports/agent.conf"))
			if conf != "640 root:whichports-agent" {
				t.Errorf("the enrolment file is %q, want 640 root:whichports-agent", conf)
			}
			if state := b.unitState("is-enabled", "whichports-agent.timer"); state != "enabled" {
				t.Errorf("the timer is %q after an install with enroll, want enabled", state)
			}
			if state := b.unitState("is-active", "whichports-agent.timer"); state != "active" {
				t.Errorf("the timer is %q after an install with enroll, want active", state)
			}
			// The one collection ran and got as far as delivery, which is
			// where a name that cannot resolve stops it.
			journal := b.mustSh("for i in $(seq 50); do" +
				" out=$(journalctl -q -u whichports-agent.service --since=@" + since + " -o cat --no-pager);" +
				" case \"$out\" in *'read config'*|*'deliver report'*) break ;; esac; sleep 0.1; done;" +
				" printf '%s\\n' \"$out\"")
			if !strings.Contains(journal, "deliver report") {
				t.Errorf("the installer's one collection never reached delivery:\n%s", journal)
			}
		})
	}
}

// TestCleanBoxAHalfDownloadedInstallerDoesNothing cuts the script at four
// places and pipes each piece in with the window's arguments. Nothing may be
// installed, enrolled or started by any of them. The empty one is the failed
// download itself.
func TestCleanBoxAHalfDownloadedInstallerDoesNothing(t *testing.T) {
	f := requireFixture(t)
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			served := f.serve(t, f.repoOld)
			b := startBox(t, fam, fam.image, served)

			size := strings.TrimSpace(b.mustSh("wc -c < /repo/install.sh"))
			for _, piece := range []string{
				"printf ''",
				"head -c 3000 /repo/install.sh",
				"head -c 9000 /repo/install.sh",
				// Everything but the last five bytes, which cuts the braced
				// call on the last line short.
				"head -c $((" + size + " - 5)) /repo/install.sh",
			} {
				out, _ := b.sh(piece + " | sudo sh -s -- " + enrolArguments)
				if strings.Contains(out, "signing key verified") || strings.Contains(out, "installing") {
					t.Errorf("`%s` piped into sh started an install:\n%s", piece, out)
				}
				assertNothingInstalled(t, b)
				b.mustNotExist("/etc/whichports/agent.conf", "a cut-off installer enrolled the server: "+piece)
				b.mustNotExist("/etc/apt/sources.list.d/whichports.list", "a cut-off installer configured apt: "+piece)
				b.mustNotExist("/etc/yum.repos.d/whichports.repo", "a cut-off installer configured dnf: "+piece)
			}
		})
	}
}

// TestCleanBoxAnOldCommandStillWorks is a command copied before 0.1.12, or
// handed out by a control plane that has not been upgraded: the installer
// with no arguments, then the enrolment chained after it. The installer must
// still install and start nothing, and the agent must be where sudo finds it.
func TestCleanBoxAnOldCommandStillWorks(t *testing.T) {
	f := requireFixture(t)
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			served := f.serve(t, f.repoOld)
			b := startBox(t, fam, fam.image, served)

			out, err := b.sh("curl -fsSL file:///repo/install.sh | sudo sh" +
				" && sudo whichports-agent " + enrolArguments +
				" && sudo systemctl enable --now whichports-agent.timer")
			if err != nil {
				t.Fatalf("the command as it was written before 0.1.12 failed: %v\n%s", err, out)
			}
			if !strings.Contains(out, "installed. Next steps:") {
				t.Errorf("with no arguments the installer did not close with its next steps:\n%s", out)
			}
			if strings.Contains(out, "connecting this server") {
				t.Errorf("with no arguments the installer connected the server by itself:\n%s", out)
			}
			if state := b.unitState("is-enabled", "whichports-agent.timer"); state != "enabled" {
				t.Errorf("the timer is %q after the chained command, want enabled", state)
			}
			b.mustExist("/etc/whichports/agent.conf", "the chained enrolment wrote it")
		})
	}
}
