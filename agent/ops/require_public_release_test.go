// Tests for require-public-release.sh, the guard publish.sh runs before it
// tags anything, run against real throwaway git repositories the way
// require_clean_main_test.go runs the other guard.
//
// What it guards. publish.sh puts selfhost.sh on get.whichports.com: the
// self-hosted installer with a release tag and that tag's commit filled in.
// On a server the installer clones the public repository and builds nothing
// unless the tag there names that very commit. The public repository has a
// history of its own, made by export/export.py, so the commit must be the
// public repository's. A copy stamped with this repository's commit would
// stop on every server that ran it.
package ops

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The files both sides hold. The public side holds them as the export copies
// them, file for file, and a README of its own the way the export adds one.
var releaseSources = map[string]string{
	"agent/cmd/agent/main.go":      "package main\n",
	"selfhost/install.sh":          "RELEASE_TAG=\nRELEASE_COMMIT=\n",
	"controlplane/app/ingest.py":   "# the ingest\n",
	"controlplane/app/__init__.py": "",
}

type releaseRepos struct {
	here   string // this repository, at the commit being published
	github string // the public repository, where the installer clones from
	public string // the owner's clone of it, with github as its origin
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func commitAll(t *testing.T, dir, message string) {
	t.Helper()
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", message)
}

func revParse(t *testing.T, dir, rev string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", rev)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git rev-parse %s in %s: %v", rev, dir, err)
	}
	return strings.TrimSpace(string(out))
}

// newReleaseRepos makes the three repositories as they stand on the day of a
// release: the public repository's commit holds this commit's sources, it
// carries the tag, and the owner's clone has both.
func newReleaseRepos(t *testing.T, tag string, annotated bool) releaseRepos {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell guard is not exercised on Windows")
	}
	here := newRepo(t)
	writeFiles(t, here, releaseSources)
	commitAll(t, here, "the release")

	github := newRepo(t)
	writeFiles(t, github, releaseSources)
	writeFiles(t, github, map[string]string{"README.md": "the public README\n"})
	commitAll(t, github, "whichports "+tag)
	if annotated {
		git(t, github, "tag", "-a", tag, "-m", "the release")
	} else {
		git(t, github, "tag", tag)
	}

	public := t.TempDir()
	git(t, public, "-c", "init.defaultBranch=main", "clone", "-q", github, public)
	git(t, public, "config", "user.email", "test@example.com")
	git(t, public, "config", "user.name", "Test")
	return releaseRepos{here: here, github: github, public: public}
}

// runPublicGuard runs the real script from this repository's root, the way
// publish.sh runs it from agent/, and returns its exit code and its words.
func runPublicGuard(t *testing.T, here, public, tag string) (int, string) {
	t.Helper()
	script, err := filepath.Abs("require-public-release.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", script, public, tag)
	cmd.Dir = here
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	if !asExitError(err, &exitErr) {
		t.Fatalf("running the guard: %v\n%s", err, out)
	}
	return exitErr.ExitCode(), string(out)
}

func TestAReleaseThePublicRepositoryHasIsAllowed(t *testing.T) {
	repos := newReleaseRepos(t, "v1.2.3", false)
	code, out := runPublicGuard(t, repos.here, repos.public, "v1.2.3")
	if code != 0 {
		t.Fatalf("the public repository has the release and the guard refused: exit %d\n%s", code, out)
	}
	if want := revParse(t, repos.github, "v1.2.3^{commit}"); !strings.Contains(out, want) {
		t.Errorf("the guard did not name the public commit %s:\n%s", want, out)
	}
}

// An annotated tag is an object of its own. The installer reads the commit it
// names, refs/tags/<tag>^{commit}, so the guard must compare that and not the
// tag object's own id.
func TestAnAnnotatedTagIsReadAsTheCommitItNames(t *testing.T) {
	repos := newReleaseRepos(t, "v1.2.3", true)
	if code, out := runPublicGuard(t, repos.here, repos.public, "v1.2.3"); code != 0 {
		t.Fatalf("an annotated tag of the right commit was refused: exit %d\n%s", code, out)
	}
}

func TestNoCloneOfThePublicRepositoryIsRefused(t *testing.T) {
	repos := newReleaseRepos(t, "v1.2.3", false)
	missing := filepath.Join(t.TempDir(), "not-there")
	code, out := runPublicGuard(t, repos.here, missing, "v1.2.3")
	if code == 0 {
		t.Fatalf("a folder that is not there was taken for the public repository:\n%s", out)
	}
	if !strings.Contains(out, "no clone of the public repository at "+missing) ||
		!strings.Contains(out, "WHICHPORTS_PUBLIC") {
		t.Errorf("the refusal does not say what is missing and how to name it:\n%s", out)
	}
}

// This repository is not the public one, even though it holds the tag and
// the same files. Taken for it, the stamp would name a commit the public
// repository does not have.
func TestThisRepositoryIsNeverTakenForThePublicOne(t *testing.T) {
	repos := newReleaseRepos(t, "v1.2.3", false)
	git(t, repos.here, "tag", "v1.2.3")
	for _, public := range []string{repos.here, filepath.Join(repos.here, "selfhost")} {
		code, out := runPublicGuard(t, repos.here, public, "v1.2.3")
		if code == 0 {
			t.Fatalf("%s, this repository, was taken for the public one:\n%s", public, out)
		}
		if !strings.Contains(out, "is this repository") {
			t.Errorf("the refusal does not say why:\n%s", out)
		}
	}
}

func TestACloneWithoutTheTagIsRefusedWithTheStepsThatMakeIt(t *testing.T) {
	repos := newReleaseRepos(t, "v1.2.3", false)
	code, out := runPublicGuard(t, repos.here, repos.public, "v1.2.4")
	if code == 0 {
		t.Fatalf("a release the public repository does not have was allowed:\n%s", out)
	}
	for _, want := range []string{
		"has no tag v1.2.4",
		"python3 export/export.py --into " + repos.public + ` --subject "whichports v1.2.4"`,
		"git -C " + repos.public + " tag v1.2.4",
		"git -C " + repos.public + " push origin main v1.2.4",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal lacks %q:\n%s", want, out)
		}
	}
}

// Tagged in the clone and never pushed: the installer clones the public
// repository, which does not have the tag.
func TestATagOnlyInTheCloneIsRefused(t *testing.T) {
	repos := newReleaseRepos(t, "v1.2.3", false)
	git(t, repos.public, "tag", "v1.2.4")
	code, out := runPublicGuard(t, repos.here, repos.public, "v1.2.4")
	if code == 0 {
		t.Fatalf("a tag the public repository does not have was allowed:\n%s", out)
	}
	if !strings.Contains(out, "not in the public repository") ||
		!strings.Contains(out, "git -C "+repos.public+" push origin main v1.2.4") {
		t.Errorf("the refusal does not say the tag is missing there and how to send it:\n%s", out)
	}
}

// The public repository's tag was moved to another commit after the clone
// read it. The installer would clone the public one's.
func TestATagThePublicRepositoryHasOnAnotherCommitIsRefused(t *testing.T) {
	repos := newReleaseRepos(t, "v1.2.3", false)
	inClone := revParse(t, repos.public, "v1.2.3^{commit}")
	writeFiles(t, repos.github, map[string]string{"README.md": "moved\n"})
	commitAll(t, repos.github, "another commit")
	git(t, repos.github, "tag", "-f", "v1.2.3")
	onGithub := revParse(t, repos.github, "v1.2.3^{commit}")

	code, out := runPublicGuard(t, repos.here, repos.public, "v1.2.3")
	if code == 0 {
		t.Fatalf("two commits under one tag were allowed:\n%s", out)
	}
	if !strings.Contains(out, inClone) || !strings.Contains(out, onGithub) {
		t.Errorf("the refusal does not name both commits, %s and %s:\n%s", inClone, onGithub, out)
	}
}

// The public release is the export of an older commit: the owner exported,
// then this repository moved on. Each of the three folders is tried alone.
func TestAPublicReleaseOfAnotherCommitIsRefused(t *testing.T) {
	for _, path := range []string{"agent/cmd/agent/main.go", "selfhost/install.sh", "controlplane/app/ingest.py"} {
		t.Run(path, func(t *testing.T) {
			repos := newReleaseRepos(t, "v1.2.3", false)
			writeFiles(t, repos.here, map[string]string{path: "changed after the export\n"})
			commitAll(t, repos.here, "a change after the export")
			code, out := runPublicGuard(t, repos.here, repos.public, "v1.2.3")
			if code == 0 {
				t.Fatalf("a public release without this commit's %s was allowed:\n%s", path, out)
			}
			folder := strings.SplitN(path, "/", 2)[0]
			if folder == "controlplane" {
				folder = "controlplane/app"
			}
			if !strings.Contains(out, "the public repository's "+folder+"/ is not this commit's") {
				t.Errorf("the refusal does not name %s/:\n%s", folder, out)
			}
		})
	}
}

// No answer from the public repository is not its agreement.
func TestAPublicRepositoryThatCannotBeReadIsRefused(t *testing.T) {
	repos := newReleaseRepos(t, "v1.2.3", false)
	if err := os.RemoveAll(repos.github); err != nil {
		t.Fatal(err)
	}
	code, out := runPublicGuard(t, repos.here, repos.public, "v1.2.3")
	if code == 0 {
		t.Fatalf("a public repository nobody could read was taken as agreeing:\n%s", out)
	}
	if !strings.Contains(out, "could not read the public repository's tags") {
		t.Errorf("the refusal does not say it could not look:\n%s", out)
	}
}

// The guard reads. It leaves the clone and both repositories as they were.
func TestTheGuardChangesNothing(t *testing.T) {
	repos := newReleaseRepos(t, "v1.2.3", false)
	before := map[string]string{}
	for _, dir := range []string{repos.here, repos.github, repos.public} {
		before[dir] = gitOutput(t, dir, "for-each-ref") + gitOutput(t, dir, "status", "--porcelain")
	}
	runPublicGuard(t, repos.here, repos.public, "v1.2.3")
	runPublicGuard(t, repos.here, repos.public, "v1.2.4")
	for dir, was := range before {
		if now := gitOutput(t, dir, "for-each-ref") + gitOutput(t, dir, "status", "--porcelain"); now != was {
			t.Errorf("the guard changed %s:\nbefore\n%s\nafter\n%s", dir, was, now)
		}
	}
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s in %s: %v", strings.Join(args, " "), dir, err)
	}
	return string(out)
}
