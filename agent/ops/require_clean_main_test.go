// Package ops tests the publish guard, require-clean-main.sh. The guard is the
// one thing publish.sh does before it tags a commit and pushes that tag, so a
// wrong answer here either blocks every publish or ships a tag that does not
// match what was built. It is shell, so the test runs the real script against
// real one-commit git repositories put into each state that matters and asserts
// on the exit code and on what the script printed.
//
// This follows the same reproduce-then-guard pattern as
// agent/packaging/scripts_test.go: the guard used to reject any untracked file,
// so a stray scratch file or a git worktree in a scratch folder made a clean publish
// impossible, and the operator worked around it by committing straight to main
// (docs/RECORD.md, 2026-08-15). The untracked-file cases below fail against that
// old logic and pass against the fix, which only inspects tracked files.
package ops

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// newRepo makes a throwaway git repository on branch main with exactly one
// committed, tracked file, and returns its path. Every case starts from this
// clean state and then dirties the tree in one specific way.
func newRepo(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell guard is not exercised on Windows")
	}

	dir := t.TempDir()

	// init.defaultBranch is set explicitly so the test does not depend on the
	// machine's git config, where the initial branch may be main or master.
	git(t, dir, "-c", "init.defaultBranch=main", "init")
	git(t, dir, "config", "user.email", "test@example.com")
	git(t, dir, "config", "user.name", "Test")

	if err := os.WriteFile(filepath.Join(dir, "tracked.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatalf("writing tracked file: %v", err)
	}
	git(t, dir, "add", "tracked.txt")
	git(t, dir, "commit", "-m", "initial")
	return dir
}

// git runs one git command in dir and fails the test if it errors. It is only
// for arranging the repository, not for the thing under test.
func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// runGuard runs the real guard script with dir as its working directory and
// returns its exit code and everything it printed. Exit code 0 means the guard
// allowed the publish.
func runGuard(t *testing.T, dir string) (int, string) {
	t.Helper()
	script, err := filepath.Abs("require-clean-main.sh")
	if err != nil {
		t.Fatalf("resolving guard path: %v", err)
	}
	cmd := exec.Command("sh", script)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	if !asExitError(err, &exitErr) {
		t.Fatalf("running guard: %v\n%s", err, out)
	}
	return exitErr.ExitCode(), string(out)
}

// asExitError unwraps an *exec.ExitError without pulling in errors.As at the
// call site, kept as a named helper so runGuard reads plainly.
func asExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// A clean tree on main is the whole point: the guard must allow it.
func TestGuardAllowsCleanMain(t *testing.T) {
	dir, _ := newRepoWithOrigin(t)
	code, out := runGuard(t, dir)
	if code != 0 {
		t.Fatalf("guard blocked a clean main (exit %d):\n%s", code, out)
	}
}

// The bug this file exists for. An untracked file changes neither HEAD nor any
// tracked file, so it cannot make the built package disagree with the tagged
// commit. The guard must let it through.
func TestGuardAllowsUntrackedFile(t *testing.T) {
	dir, _ := newRepoWithOrigin(t)
	if err := os.WriteFile(filepath.Join(dir, "scratch.log"), []byte("noise\n"), 0o644); err != nil {
		t.Fatalf("writing untracked file: %v", err)
	}
	code, out := runGuard(t, dir)
	if code != 0 {
		t.Fatalf("guard blocked an untracked scratch file (exit %d):\n%s", code, out)
	}
}

// An untracked directory, which is what a git worktree in a scratch folder
// looks like from the parent checkout. Same reasoning as the single file: it is
// not tracked, so it is not part of a release.
func TestGuardAllowsUntrackedDirectory(t *testing.T) {
	dir, _ := newRepoWithOrigin(t)
	sub := filepath.Join(dir, "worktree-scratch")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("making untracked dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "file.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatalf("writing file in untracked dir: %v", err)
	}
	code, out := runGuard(t, dir)
	if code != 0 {
		t.Fatalf("guard blocked an untracked directory (exit %d):\n%s", code, out)
	}
}

// An uncommitted edit to a tracked file is exactly what must be caught: it would
// be compiled into the package but is absent from the commit the tag points at.
// The guard must fail and must name the offending file, because "not clean" with
// no detail is the frustration this whole change is fixing.
func TestGuardBlocksModifiedTrackedFile(t *testing.T) {
	dir, _ := newRepoWithOrigin(t)
	if err := os.WriteFile(filepath.Join(dir, "tracked.txt"), []byte("one\ntwo\n"), 0o644); err != nil {
		t.Fatalf("modifying tracked file: %v", err)
	}
	code, out := runGuard(t, dir)
	if code == 0 {
		t.Fatalf("guard allowed a modified tracked file:\n%s", out)
	}
	if !strings.Contains(out, "tracked.txt") {
		t.Fatalf("guard did not name the offending file:\n%s", out)
	}
}

// A staged-but-uncommitted new file is a tracked change in the index, so it must
// be caught too. --untracked-files=no suppresses only "??" entries, not staged
// additions, and this proves the distinction holds.
func TestGuardBlocksStagedNewFile(t *testing.T) {
	dir, _ := newRepoWithOrigin(t)
	if err := os.WriteFile(filepath.Join(dir, "added.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatalf("writing new file: %v", err)
	}
	git(t, dir, "add", "added.txt")
	code, out := runGuard(t, dir)
	if code == 0 {
		t.Fatalf("guard allowed a staged new file:\n%s", out)
	}
	if !strings.Contains(out, "added.txt") {
		t.Fatalf("guard did not name the staged file:\n%s", out)
	}
}

// Publishing tags HEAD, so it must happen on main. Any other branch is refused,
// and the message names the branch so the operator knows where they are.
func TestGuardBlocksNonMainBranch(t *testing.T) {
	dir, _ := newRepoWithOrigin(t)
	git(t, dir, "checkout", "-b", "feature")
	code, out := runGuard(t, dir)
	if code == 0 {
		t.Fatalf("guard allowed publishing from a non-main branch:\n%s", out)
	}
	if !strings.Contains(out, "feature") {
		t.Fatalf("guard did not name the current branch:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// The commit being published has to be one origin already has.
//
// docs/RECORD.md 4.49 and 4.57. A publish tags the current commit and pushes
// the tag. If local main has commits origin/main does not, the tag lands on a
// commit nobody else can fetch, and 4.57 records the result: a 0.1.6 package
// live at get.whichports.com that no tag and no commit on main accounts for.
// The guard checked the branch name and the working tree and never checked
// that the two mains agreed.

// newRepoWithOrigin returns (clone, origin) where clone is on main and even
// with origin.
//
// Every test about the working tree uses this rather than newRepo, because the
// guard now also requires agreement with origin and a repository with no remote
// fails that first. They are still testing what they were written to test: the
// origin half is simply a precondition they now have to satisfy, the way they
// already had to be on main. newRepo stays for the one test whose subject is a
// missing origin.
func newRepoWithOrigin(t *testing.T) (string, string) {
	t.Helper()
	origin := newRepo(t)
	git(t, origin, "config", "receive.denyCurrentBranch", "ignore")

	clone := t.TempDir()
	git(t, clone, "-c", "init.defaultBranch=main", "clone", origin, clone)
	git(t, clone, "config", "user.email", "test@example.com")
	git(t, clone, "config", "user.name", "Test")
	return clone, origin
}

func TestGuardAllowsAMainThatOriginAlreadyHas(t *testing.T) {
	clone, _ := newRepoWithOrigin(t)
	if code, out := runGuard(t, clone); code != 0 {
		t.Fatalf("a clone even with origin was refused: exit %d, %s", code, out)
	}
}

func TestGuardBlocksACommitOriginDoesNotHave(t *testing.T) {
	// The 4.57 shape exactly: committed, clean, on main, and one commit ahead
	// of origin. Publishing here tags a commit nobody can fetch.
	clone, _ := newRepoWithOrigin(t)
	if err := os.WriteFile(filepath.Join(clone, "tracked.txt"), []byte("two\n"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	git(t, clone, "commit", "-am", "a local-only commit")

	code, out := runGuard(t, clone)
	if code == 0 {
		t.Fatalf("a commit origin does not have was allowed to publish: %s", out)
	}
	if !strings.Contains(out, "origin") {
		t.Fatalf("the refusal does not mention origin, so nobody will know what to do: %s", out)
	}
}

func TestGuardBlocksAMainBehindOrigin(t *testing.T) {
	// Behind is not the 4.57 failure, but publishing an old tree as the newest
	// version ships a package older than main and is never intended.
	clone, origin := newRepoWithOrigin(t)
	if err := os.WriteFile(filepath.Join(origin, "tracked.txt"), []byte("newer\n"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	git(t, origin, "commit", "-am", "moved on without us")
	git(t, clone, "fetch", "origin")

	if code, out := runGuard(t, clone); code == 0 {
		t.Fatalf("a main behind origin was allowed to publish: %s", out)
	}
}

func TestGuardSaysSoWhenThereIsNoOriginAtAll(t *testing.T) {
	// A repository with no remote cannot be checked against one. Refusing is
	// the safe direction, and the message has to say which of the two problems
	// it is or the operator will go looking for uncommitted changes.
	dir := newRepo(t)
	code, out := runGuard(t, dir)
	if code == 0 {
		t.Fatalf("a repository with no origin was allowed to publish: %s", out)
	}
	if !strings.Contains(out, "origin") {
		t.Fatalf("the refusal does not name the missing origin: %s", out)
	}
}

func TestGuardRefusesWhenOriginCannotBeReached(t *testing.T) {
	// Found by mutation. An origin that exists but cannot be fetched is the
	// dangerous case: without this the guard compares against a stale
	// remote-tracking ref, which is precisely the drifted local view it was
	// added to catch. Not being able to look is not the same as having looked.
	//
	// The no-origin test does not cover this, because there the first check
	// fires. Here the remote is configured and points at nothing.
	clone, _ := newRepoWithOrigin(t)
	git(t, clone, "remote", "set-url", "origin", filepath.Join(t.TempDir(), "gone"))

	code, out := runGuard(t, clone)
	if code == 0 {
		t.Fatalf("an unreachable origin was allowed to publish: %s", out)
	}
	if !strings.Contains(out, "fetch") {
		t.Fatalf("the refusal does not say the fetch failed, so the operator will go\n"+
			"looking for uncommitted changes instead: %s", out)
	}
}

func TestTheTwoOriginRefusalsAreDistinguishable(t *testing.T) {
	// Also from mutation: deleting the missing-origin check left the suite
	// green, because the fetch check catches that case too and both messages
	// contain the word origin. They are different faults with different fixes,
	// so the operator has to be able to tell them apart.
	noRemote := newRepo(t)
	_, missingOut := runGuard(t, noRemote)

	unreachable, _ := newRepoWithOrigin(t)
	git(t, unreachable, "remote", "set-url", "origin", filepath.Join(t.TempDir(), "gone"))
	_, unreachableOut := runGuard(t, unreachable)

	if !strings.Contains(missingOut, "no origin remote") {
		t.Fatalf("a repository with no remote should say so plainly: %s", missingOut)
	}
	if strings.Contains(unreachableOut, "no origin remote") {
		t.Fatalf("an unreachable origin is reported as a missing one: %s", unreachableOut)
	}
}
