package cleanbox

import (
	"crypto/rand"
	"encoding/hex"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// box is one clean machine: a container running real systemd as pid 1, with a
// repository tree mounted read-only at /repo.
//
// Real systemd rather than a stub, because the thing most worth asserting is
// the state of a timer, and a stubbed systemctl would happily report whatever
// the stub decided. docs/RECORD.md 4.48 is a guard that passed while not
// guarding, and a fake init would be the same mistake in a new place.
//
// The container is privileged and shares the host cgroup namespace, which is
// what systemd needs to manage its own cgroups. That is a real privilege and it
// is granted only to a throwaway container on a developer machine or a
// disposable CI runner, never to anything that outlives the test.
type box struct {
	t      *testing.T
	name   string
	served string
	fam    family
}

// startBox boots one clean box and waits for systemd to finish coming up.
func startBox(t *testing.T, fam family, image, served string) *box {
	t.Helper()
	name := "whichports-cleanbox-" + randomSuffix(t)
	args := []string{
		"run", "-d", "--name", name,
		"--platform=linux/amd64",
		"--privileged", "--cgroupns=host",
		"--tmpfs", "/run", "--tmpfs", "/run/lock",
		"-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
		"-v", served + ":/repo:ro",
		image,
	}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("starting %s from %s: %v\n%s", name, image, err, out)
	}
	b := &box{t: t, name: name, served: served, fam: fam}
	t.Cleanup(func() {
		exec.Command("docker", "rm", "-f", name).Run()
	})
	b.waitForSystemd()
	b.assertRepositoryIsReadable()
	return b
}

// assertRepositoryIsReadable checks the mounted repository the way the two
// things that actually read it do: as an unprivileged user.
//
// It exists because of a failure that passed on a Mac and failed in CI. apt
// drops to the _apt user for every fetch, and a bind-mounted directory carries
// the host's real modes on Linux while Docker Desktop on macOS flattens them.
// A 0700 fixture therefore looked fine locally and made apt fail with a
// permission error that reads nothing like its cause. Asserting it here means
// the next person gets told what is wrong instead of reading an apt error.
func (b *box) assertRepositoryIsReadable() {
	b.t.Helper()
	// 65534 is nobody on both families.
	out, err := dockerOutput("exec", "--user", "65534", b.name,
		"test", "-r", "/repo/install.sh")
	if err != nil {
		b.t.Fatalf("the mounted repository is not readable by an unprivileged user "+
			"on %s, so apt would fail to fetch rather than fail to verify. The served "+
			"tree needs 0755 directories and 0644 files, which is what a published "+
			"repository has: %v\n%s", b.fam.name, err, out)
	}
}

// startBare runs one of the untouched distribution images with a command that
// only waits. Those images carry no init, which is the point: they are the
// place to ask what the published one-liner does on a box that has nothing.
func startBare(t *testing.T, fam family, served string) *box {
	t.Helper()
	name := "whichports-cleanbox-bare-" + randomSuffix(t)
	args := []string{
		"run", "-d", "--name", name,
		"--platform=linux/amd64",
		"-v", served + ":/repo:ro",
		fam.baseImage, "sleep", "infinity",
	}
	if out, err := dockerOutput(args...); err != nil {
		t.Fatalf("starting %s from %s: %v\n%s", name, fam.baseImage, err, out)
	}
	t.Cleanup(func() {
		exec.Command("docker", "rm", "-f", name).Run()
	})
	b := &box{t: t, name: name, served: served, fam: fam}
	b.assertRepositoryIsReadable()
	return b
}

// dockerOutput runs one docker command and returns its combined output.
func dockerOutput(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).CombinedOutput()
	return string(out), err
}

// waitForSystemd blocks until the init system reports it has finished starting.
// A container is allowed to end up degraded, because units that want hardware
// this machine does not have will fail there and none of them are ours.
func (b *box) waitForSystemd() {
	b.t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		out, _ := exec.Command("docker", "exec", b.name,
			"systemctl", "is-system-running").CombinedOutput()
		last = strings.TrimSpace(string(out))
		if last == "running" || last == "degraded" {
			return
		}
		time.Sleep(time.Second)
	}
	logs, _ := exec.Command("docker", "logs", b.name).CombinedOutput()
	b.t.Fatalf("systemd never came up in %s (last state %q). "+
		"Every timer assertion in this file depends on a real init, so this is a "+
		"failure and not something to work around.\ncontainer log:\n%s",
		b.name, last, logs)
}

// run executes one command in the box and returns its combined output.
func (b *box) run(argv ...string) (string, error) {
	b.t.Helper()
	args := append([]string{"exec", b.name}, argv...)
	out, err := exec.Command("docker", args...).CombinedOutput()
	return string(out), err
}

// mustRun executes one command and fails the test if it does not succeed.
func (b *box) mustRun(argv ...string) string {
	b.t.Helper()
	out, err := b.run(argv...)
	if err != nil {
		b.t.Fatalf("%v failed in %s: %v\n%s", argv, b.name, err, out)
	}
	return out
}

// mustFail executes one command and fails the test if it succeeds. It is how
// the negative assertions are made: a check that never refuses anything is not
// a check.
func (b *box) mustFail(why string, argv ...string) string {
	b.t.Helper()
	out, err := b.run(argv...)
	if err == nil {
		b.t.Fatalf("%v succeeded in %s and it must not: %s\noutput:\n%s",
			argv, b.name, why, out)
	}
	return out
}

// sh runs a shell line, for the few places that genuinely need a pipeline.
func (b *box) sh(script string) (string, error) {
	b.t.Helper()
	return b.run("sh", "-c", script)
}

func (b *box) mustSh(script string) string {
	b.t.Helper()
	out, err := b.sh(script)
	if err != nil {
		b.t.Fatalf("shell line failed in %s: %s\n%v\n%s", b.name, script, err, out)
	}
	return out
}

// install runs the published one-liner's local equivalent: fetch the script and
// pipe it into sh, exactly as the page tells an operator to.
func (b *box) install() (string, error) {
	b.t.Helper()
	return b.sh("curl -fsSL file:///repo/install.sh | sh")
}

// mustInstall runs the installer and fails if it does not complete.
func (b *box) mustInstall() string {
	b.t.Helper()
	out, err := b.install()
	if err != nil {
		b.t.Fatalf("the installer did not run to completion on %s: %v\n%s",
			b.fam.name, err, out)
	}
	return out
}

// exists reports whether a path is present in the box.
func (b *box) exists(path string) bool {
	b.t.Helper()
	_, err := b.run("test", "-e", path)
	return err == nil
}

// mustExist fails unless the path is present, naming what was expected to put
// it there. Asserting a thing is there before asserting it is correct is the
// habit this repository learned the hard way.
func (b *box) mustExist(path, why string) {
	b.t.Helper()
	if !b.exists(path) {
		b.t.Fatalf("%s is missing on %s, expected because %s", path, b.fam.name, why)
	}
}

func (b *box) mustNotExist(path, why string) {
	b.t.Helper()
	if b.exists(path) {
		b.t.Fatalf("%s is still present on %s, and should not be because %s",
			path, b.fam.name, why)
	}
}

// unitState returns what systemd says about a unit, trimmed. is-enabled and
// is-active both exit non-zero for ordinary answers such as disabled and
// inactive, so the error is deliberately ignored and the word is what counts.
func (b *box) unitState(query, unit string) string {
	b.t.Helper()
	out, _ := b.run("systemctl", query, unit)
	return strings.TrimSpace(out)
}

// installedVersion asks the package manager, not the filesystem.
func (b *box) installedVersion() string {
	b.t.Helper()
	switch b.fam.name {
	case "ubuntu-26.04":
		out, err := b.run("dpkg-query", "-W", "-f=${Version}", "whichports-agent")
		if err != nil {
			return ""
		}
		return strings.TrimSpace(out)
	default:
		out, err := b.run("rpm", "-q", "--qf", "%{VERSION}", "whichports-agent")
		if err != nil {
			return ""
		}
		return strings.TrimSpace(out)
	}
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("random: %v", err)
	}
	return hex.EncodeToString(buf)
}
