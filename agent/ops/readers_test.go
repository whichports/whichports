// Tests that the release build holds the two readers, run against the real
// agent built as a release is.
//
// The package reader and the apt lists reader beside it stood behind a build
// tag until the security data check shipped, and a release was built with no
// tag, so no published agent held either (docs/RECORD.md 4.369 and 4.385).
// Since 2026-10-12 neither has a constraint line and every build holds both
// (docs/SPEC-packages-switch.md, "The day the check ships"). These tests read
// the binary rather than the build commands, because the binary is what
// reaches a server.
package ops

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// readerMark is dpkg's own directory, which the reader cannot read a record
// without naming (internal/collect/packages.go, dpkgDir). It is looked for in
// the binary's bytes, so a binary with its symbols stripped still shows it.
const readerMark = "var/lib/dpkg"

// listsReaderMark is apt's own folder of lists, which the lists reader cannot
// read a list without naming (internal/collect/aptlists.go, aptListsDir).
const listsReaderMark = "var/lib/apt/lists"

// keptFileMark is the name of the file the agent keeps beside its state file
// in timer mode (cmd/agent/packages.go, keptListsName).
const keptFileMark = "apt-lists.json"

// listsReaderSymbol is the lists reader's own function as `go tool nm` prints
// it. The entry point it is called from is the package reader's.
const listsReaderSymbol = "/internal/collect.collectOffers"

// readerSymbol is the reader's entry point as `go tool nm` prints it. It was
// CollectPackages until the apt lists reader came to share the entry point:
// CollectPackages is now two lines that call this one, which the compiler
// folds into its caller, so it is no symbol in any binary. The test below
// proves the probe sees this name in a build that has the reader.
const readerSymbol = "/internal/collect.CollectPackagesKeeping"

// buildAgent builds the real agent the way ops/release-build.sh does, static
// and for linux amd64, with the given build tags, and returns the binary's
// path. One flag differs from the release: -buildvcs=false, because these
// builds are read for what they hold and not for which commit they are, and
// a test must also run from a tree with scratch in it.
//
// stripped adds -s -w, which a release does not pass. It is here so the claim
// that the mark outlives stripping is run and not assumed.
func buildAgent(t *testing.T, tags string, stripped bool) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH")
	}
	out := filepath.Join(t.TempDir(), "agent")
	args := []string{"build", "-trimpath", "-buildvcs=false"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	ldflags := "-X main.version=9.9.9"
	if stripped {
		ldflags += " -s -w"
	}
	args = append(args, "-ldflags", ldflags, "-o", out, "./cmd/agent")
	build := exec.Command("go", args...)
	build.Dir = ".."
	// GOFLAGS is emptied so a tag given to this test run does not reach the
	// build that is meant to have none.
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOFLAGS=")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return out
}

func holds(t *testing.T, binary, mark string) bool {
	t.Helper()
	content, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Contains(content, []byte(mark))
}

func holdsTheSymbol(t *testing.T, binary, symbol string) bool {
	t.Helper()
	out, err := exec.Command("go", "tool", "nm", binary).Output()
	if err != nil {
		t.Fatalf("go tool nm %s: %v", binary, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), symbol) {
			return true
		}
	}
	return false
}

// The build that is released holds both readers: the entry point they share,
// the lists reader's own function, the two folders they read and the name of
// the file the agent keeps. Built with no tag, as ops/release-build.sh
// builds, because there is no tag any more.
func TestTheReleaseBuildHoldsBothReaders(t *testing.T) {
	released := buildAgent(t, "", false)
	for _, mark := range []string{readerMark, listsReaderMark, keptFileMark} {
		if !holds(t, released, mark) {
			t.Errorf("the release build does not hold %q, so a reader is not in it", mark)
		}
	}
	for _, symbol := range []string{readerSymbol, listsReaderSymbol} {
		if !holdsTheSymbol(t, released, symbol) {
			t.Errorf("the release build does not hold the symbol %s", symbol)
		}
	}
}

// The marks are the readers' own: each is the folder its source names, and
// the kept file's name is the one the agent writes.
func TestTheMarksAreTheOnesTheReadersCarry(t *testing.T) {
	for file, text := range map[string]string{
		filepath.Join("..", "internal", "collect", "packages.go"): `const dpkgDir = "` + readerMark + `"`,
		filepath.Join("..", "internal", "collect", "aptlists.go"): `const aptListsDir = "` + listsReaderMark + `"`,
		filepath.Join("..", "cmd", "agent", "packages.go"):        `keptListsName = "` + keptFileMark + `"`,
	} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(source), text) {
			t.Errorf("%s no longer holds %s, so a mark here is stale", file, text)
		}
	}
}

// No file of the agent stands behind the tag any more, and the file that
// stood in for the readers in a build without it is gone. A constraint line
// left on one file would leave that file out of every release in silence,
// since no build command passes a tag.
func TestNoFileOfTheAgentIsBehindTheOldTag(t *testing.T) {
	err := filepath.WalkDir("..", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(source), "\n") {
			if strings.HasPrefix(line, "//go:build") && strings.Contains(line, "whichports_"+"packages") {
				t.Errorf("%s is still behind the tag: %s", path, line)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join("..", "cmd", "agent", "packages_off.go")); err == nil {
		t.Error("cmd/agent/packages_off.go is still there, the stand-in for a build without the readers")
	}
}

// The release guard refuses neither reader any more. It still refuses a
// binary built with any tag, which TestGuardRefusesABinaryBuiltWithATag
// holds.
func TestTheGuardRefusesNeitherReader(t *testing.T) {
	guard, err := os.ReadFile("require-reproducible-binary.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, mark := range []string{readerMark, listsReaderMark} {
		if strings.Contains(string(guard), mark) {
			t.Errorf("the release guard still names %q", mark)
		}
	}
	if !strings.Contains(string(guard), "A release is built with no build tag.") {
		t.Error("the release guard no longer refuses a binary built with a tag")
	}
}

// A release is built with no build tag, so no build command of ours may pass
// one. The guard refuses a tagged binary too, but `make agent` builds the
// packages for hands-on testing and never meets the guard.
func TestNoBuildCommandPassesATag(t *testing.T) {
	for _, path := range []string{filepath.Join("..", "Makefile"), "release-build.sh"} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		// A command continued over two lines is read as one. Only the build
		// commands are read: `git describe --tags` is about git's tags.
		joined := strings.ReplaceAll(string(content), "\\\n", " ")
		builds := 0
		for _, line := range strings.Split(joined, "\n") {
			if !strings.Contains(line, "go build") || strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			builds++
			if strings.Contains(line, "-tags") {
				t.Errorf("%s passes a build tag, and a release is built with none:\n%s", path, line)
			}
		}
		if builds == 0 {
			t.Fatalf("%s holds no go build command, so this test reads the wrong file", path)
		}
	}
}
