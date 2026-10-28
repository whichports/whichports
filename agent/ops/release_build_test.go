// Tests for the release build and its guard, run against real throwaway git
// repositories with a real Go build in them, the way require_clean_main_test.go
// runs the publish guard against real repositories.
//
// The property under test is the one docs/RECORD.md 4.111 found broken on the
// whole fleet: a release binary must say which commit it is, and must say
// vcs.modified=false, whatever scratch is lying around the working tree. The
// toolchain counts an untracked file as a modification (cmd/go/internal/vcs,
// gitStatus: `len(git status --porcelain) > 0`), so the case that matters is a
// tree with an untracked file in it and nothing else wrong.
package ops

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// newModuleRepo makes a git repository whose root is a tiny Go module with a
// main package under cmd/agent, one commit, and copies of the two scripts under
// ops/, so release-build.sh runs in it exactly as it runs in agent/.
func newModuleRepo(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell scripts are not exercised on Windows")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH")
	}
	dir := t.TempDir()
	git(t, dir, "-c", "init.defaultBranch=main", "init")
	git(t, dir, "config", "user.email", "test@example.com")
	git(t, dir, "config", "user.name", "Test")

	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/agent\n\ngo 1.22\n")
	write("cmd/agent/main.go", "package main\n\nvar version string\n\nfunc main() { println(version) }\n")
	for _, script := range []string{"release-build.sh", "require-reproducible-binary.sh"} {
		body, err := os.ReadFile(script)
		if err != nil {
			t.Fatalf("reading %s: %v", script, err)
		}
		write(filepath.Join("ops", script), string(body))
	}
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "initial")
	return dir
}

func head(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// run runs a shell script in dir with the given arguments and environment
// additions, returning its exit code and output.
func run(t *testing.T, dir, script string, env []string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{filepath.Join("ops", script)}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	if !asExitError(err, &exitErr) {
		t.Fatalf("running %s: %v\n%s", script, err, out)
	}
	return exitErr.ExitCode(), string(out)
}

// The case the whole thing exists for: an untracked file in the working tree,
// which the publish guard rightly allows and the toolchain counts as dirty.
// The release build must still produce a binary that names the commit.
func TestReleaseBuildFromATreeWithUntrackedScratchNamesTheCommit(t *testing.T) {
	dir := newModuleRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "scratch.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := run(t, dir, "release-build.sh", []string{"PKG_VERSION=9.9.9"}, "dist/agent")
	if code != 0 {
		t.Fatalf("release build refused a tree whose only difference is an untracked file:\n%s", out)
	}
	if !strings.Contains(out, "vcs.modified=false") || !strings.Contains(out, head(t, dir)) {
		t.Fatalf("the build did not say the binary is the commit:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "dist", "agent")); err != nil {
		t.Fatalf("no binary was written: %v", err)
	}
}

// A modified tracked file is not something the release build works around: the
// worktree is of the commit, so the binary is the commit and not the edit. The
// build still succeeds, because publish.sh's own guard is what refuses an
// uncommitted tracked change, and this proves the binary cannot carry it.
func TestReleaseBuildIgnoresAnUncommittedEditAndBuildsTheCommit(t *testing.T) {
	dir := newModuleRepo(t)
	edited := "package main\n\nvar version string\n\nfunc main() { panic(\"this edit is not committed\") }\n"
	if err := os.WriteFile(filepath.Join(dir, "cmd", "agent", "main.go"), []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := run(t, dir, "release-build.sh", []string{"PKG_VERSION=9.9.9"}, "dist/agent")
	if code != 0 {
		t.Fatalf("release build failed:\n%s", out)
	}
	if !strings.Contains(out, "vcs.modified=false") {
		t.Fatalf("the binary does not say it is the commit:\n%s", out)
	}
}

// The release build leaves no worktree behind, on success.
func TestReleaseBuildRemovesItsWorktree(t *testing.T) {
	dir := newModuleRepo(t)
	if code, out := run(t, dir, "release-build.sh", []string{"PKG_VERSION=9.9.9"}, "dist/agent"); code != 0 {
		t.Fatalf("release build failed:\n%s", out)
	}
	cmd := exec.Command("git", "worktree", "list")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(strings.TrimSpace(string(out)), "\n") + 1; lines != 1 {
		t.Fatalf("expected only the main worktree, got:\n%s", out)
	}
}

// The guard on its own: a binary built straight from a dirty tree is refused,
// with the reason in words.
func TestGuardRefusesABinaryBuiltFromADirtyTree(t *testing.T) {
	dir := newModuleRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "scratch.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-trimpath", "-ldflags", "-X main.version=9.9.9", "-o", "dist/direct", "./cmd/agent")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("direct build: %v\n%s", err, out)
	}
	code, out := run(t, dir, "require-reproducible-binary.sh", nil, "dist/direct", head(t, dir))
	if code == 0 {
		t.Fatalf("the guard accepted a binary stamped from a dirty tree:\n%s", out)
	}
	if !strings.Contains(out, "vcs.modified=true") {
		t.Fatalf("the refusal does not name the stamp:\n%s", out)
	}
}

// The guard refuses a clean binary of another commit, and names the mismatch.
func TestGuardRefusesTheWrongCommit(t *testing.T) {
	dir := newModuleRepo(t)
	if code, out := run(t, dir, "release-build.sh", []string{"PKG_VERSION=9.9.9"}, "dist/agent"); code != 0 {
		t.Fatalf("release build failed:\n%s", out)
	}
	code, out := run(t, dir, "require-reproducible-binary.sh", nil, "dist/agent", strings.Repeat("0", 40))
	if code == 0 || !strings.Contains(out, "vcs.revision=") {
		t.Fatalf("wrong commit was not refused by name:\n%s", out)
	}
}

// A missing binary is a refusal, never a pass.
func TestGuardRefusesAMissingBinary(t *testing.T) {
	dir := newModuleRepo(t)
	code, _ := run(t, dir, "require-reproducible-binary.sh", nil, "dist/nothing", head(t, dir))
	if code == 0 {
		t.Fatal("a missing binary passed the guard")
	}
}

// A release is built with no build tag. The guard refuses a binary built with
// one and names it, when everything else about the binary is right: a clean
// tree and the right commit. No file of the agent stands behind a tag since
// 2026-10-12, and a tag given to a build is still not how a release is made.
func TestGuardRefusesABinaryBuiltWithATag(t *testing.T) {
	dir := newModuleRepo(t)
	build := exec.Command("go", "build", "-trimpath", "-tags", "some_tag",
		"-ldflags", "-X main.version=9.9.9", "-o", "dist/tagged", "./cmd/agent")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("tagged build: %v\n%s", err, out)
	}
	code, out := run(t, dir, "require-reproducible-binary.sh", nil, "dist/tagged", head(t, dir))
	if code == 0 {
		t.Fatalf("the guard accepted a binary built with a tag:\n%s", out)
	}
	if !strings.Contains(out, "-tags=some_tag") {
		t.Fatalf("the refusal does not name the tag:\n%s", out)
	}
	if refusals := strings.Count(out, "REFUSED"); refusals != 1 {
		t.Fatalf("the tag should be the only thing wrong with this binary, got %d refusals:\n%s", refusals, out)
	}
}

// The guard takes a binary that holds both readers, since every release does
// (docs/SPEC-packages-switch.md, "The day the check ships"). Until 2026-10-12
// it refused a binary that named either reader's folder, and this is the
// same repository and the same two marks, released.
func TestGuardTakesABinaryThatHoldsBothReaders(t *testing.T) {
	dir := newModuleRepo(t)
	holding := "package main\n\nvar version string\n\nfunc main() { println(version, \"" + readerMark + "\", \"" + listsReaderMark + "\") }\n"
	if err := os.WriteFile(filepath.Join(dir, "cmd", "agent", "main.go"), []byte(holding), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "the marks")
	code, out := run(t, dir, "release-build.sh", []string{"PKG_VERSION=9.9.9"}, "dist/agent")
	if code != 0 {
		t.Fatalf("the guard refused a binary that holds the readers' marks:\n%s", out)
	}
	if strings.Contains(out, "REFUSED") {
		t.Fatalf("a release was refused for something:\n%s", out)
	}
}
