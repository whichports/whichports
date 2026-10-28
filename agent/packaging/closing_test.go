package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// What the installer says at the end, and what the package says before it
// (docs/RECORD.md 4.460). The last lines say what was done and what is left,
// and never tell the reader to do what was just done, or what the next lines
// do: the confusion of docs/RECORD.md 4.184, where the output said to enable
// a timer the one-liner had already enabled.

// The package's postinstall prints what is left to do. With enroll the
// installer connects the server right after the package, so it tells the
// package so, and the package does not tell the reader to do what the next
// lines do. Without enroll it says nothing new.
func TestDnfTellsThePackageWhetherTheInstallerConnectsNext(t *testing.T) {
	for _, enroll := range []string{"yes", "no"} {
		for _, installed := range [][]string{rpmDependencies(t), nil} {
			run := runDnfInstall(t, enroll, installed, "")
			if len(run.env) != 1 || run.env[0] != enroll {
				t.Errorf("with ENROLL=%s dnf ran with WHICHPORTS_INSTALLER_CONNECTS=%q", enroll, run.env)
			}
		}
	}
}

func TestAptTellsThePackageWhetherTheInstallerConnectsNext(t *testing.T) {
	script := installerSource(t)
	if !strings.Contains(script, "\n  WHICHPORTS_INSTALLER_CONNECTS=\"$ENROLL\" apt-get install -y whichports-agent\n") {
		t.Error("apt-get install does not tell the package whether the installer connects next")
	}
}

// The closing lines without enroll, run for real: the installer's own lines
// after its enroll branch, with a stand-in systemctl that says whether the
// timer is on.
func plainClosingLines(t *testing.T, timerOn bool) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell scripts are not exercised on Windows")
	}
	script := installerSource(t)
	start := strings.Index(script, "\nelse\n  echo\n  echo \"installed. Next steps:\"")
	if start < 0 {
		t.Fatal("install.sh has no plain closing lines after its enroll branch")
	}
	end := strings.Index(script[start:], "\nfi\n")
	if end < 0 {
		t.Fatal("install.sh's plain closing lines have no end")
	}
	body := script[start+len("\nelse\n") : start+end]
	bin := t.TempDir()
	answer := "1"
	if timerOn {
		answer = "0"
	}
	systemctl := "#!/bin/sh\n[ \"$1\" = is-enabled ] && [ \"$2\" = whichports-agent.timer ] && exit " + answer + "\nexit 9\n"
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(systemctl), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", "set -eu\n"+body)
	cmd.Env = []string{"PATH=" + bin + ":/bin:/usr/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the plain closing lines failed: %v\n%s", err, out)
	}
	return string(out)
}

// Run again on a server whose timer is on, the plain line said to turn the
// timer on, under the package's own line saying it was already on.
func TestThePlainEndingDoesNotSayToEnableATimerThatIsOn(t *testing.T) {
	out := plainClosingLines(t, true)
	if strings.Contains(out, "systemctl enable --now") {
		t.Errorf("the ending says to enable a timer that is on:\n%s", out)
	}
	if !strings.Contains(out, "already on") {
		t.Errorf("the ending says nothing of the timer it found:\n%s", out)
	}
}

func TestThePlainEndingStillSaysHowToTurnTheTimerOn(t *testing.T) {
	out := plainClosingLines(t, false)
	if !strings.Contains(out, "every 15m:  systemctl enable --now whichports-agent.timer") {
		t.Errorf("a server with the timer off is not told how to turn it on:\n%s", out)
	}
}

// apt and dnf end the same way: the closing lines come after the branch for
// each package manager, so one set serves both, and the one-pipe line's last
// line, read on Debian 13 (docs/RECORD.md 4.330), is the last line on dnf too.
func TestAptAndDnfEndTheSameWay(t *testing.T) {
	script := installerSource(t)
	families := strings.Index(script, "\nelif command -v dnf >/dev/null 2>&1; then\n")
	refusal := strings.Index(script, "no apt or dnf found.")
	branchesEnd := -1
	if refusal >= 0 {
		if end := strings.Index(script[refusal:], "\nfi\n"); end >= 0 {
			branchesEnd = refusal + end
		}
	}
	closing := strings.Index(script, "echo \"installed and connected. This server reports every 15 minutes.\"")
	if families < 0 || branchesEnd < families || closing < branchesEnd {
		t.Fatalf("the closing line is not after the package managers' branches "+
			"(dnf %d, branches end %d, closing %d)", families, branchesEnd, closing)
	}
	rest := script[closing:]
	rest = rest[:strings.Index(rest, "\nelse\n")]
	for _, line := range strings.Split(rest, "\n")[1:] {
		if strings.Contains(line, "echo") && !strings.Contains(line, "look:") && !strings.Contains(line, "document:") {
			t.Errorf("a line after the last line of the connected ending: %s", line)
		}
	}
}
