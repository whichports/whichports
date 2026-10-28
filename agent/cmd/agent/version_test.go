package main

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"runtime/debug"
	"strings"
	"testing"
)

// The --version contract: one line, every field either what the build
// recorded or the word unknown, and a path that by construction cannot
// collect anything. The last property is tested the way internal/safety
// tests its boundaries, by scanning the source rather than trusting it.

// buildInfoWith returns a BuildInfo carrying exactly the given vcs settings,
// the shape runtime/debug produces for a binary built inside a git checkout.
func buildInfoWith(settings map[string]string) *debug.BuildInfo {
	info := &debug.BuildInfo{}
	for k, v := range settings {
		info.Settings = append(info.Settings, debug.BuildSetting{Key: k, Value: v})
	}
	return info
}

func TestVersionLineAllFieldsPresent(t *testing.T) {
	info := buildInfoWith(map[string]string{
		"vcs.revision": "0cd1ed220c51feba1bebc4d2102528c97027bf71",
		"vcs.time":     "2026-08-15T17:13:25Z",
		"vcs.modified": "false",
	})
	got := versionLine("0.1.6", info)
	want := "whichports-agent version=0.1.6" +
		" vcs.revision=0cd1ed220c51feba1bebc4d2102528c97027bf71" +
		" vcs.time=2026-08-15T17:13:25Z vcs.modified=false"
	if got != want {
		t.Errorf("versionLine:\n got %q\nwant %q", got, want)
	}
}

// A binary built with plain `go build`, outside any packaging, has neither an
// injected version nor, when built outside git, any vcs settings. Every field
// must say unknown rather than inventing a value.
func TestVersionLineNothingRecorded(t *testing.T) {
	got := versionLine("", nil)
	want := "whichports-agent version=unknown vcs.revision=unknown vcs.time=unknown vcs.modified=unknown"
	if got != want {
		t.Errorf("versionLine with nothing recorded:\n got %q\nwant %q", got, want)
	}
}

// ReadBuildInfo can succeed while carrying no vcs settings at all, which is
// what -buildvcs=false produces. The absence must read as unknown, and the
// injected package version must still be reported.
func TestVersionLineBuildInfoWithoutVcs(t *testing.T) {
	got := versionLine("0.1.7", buildInfoWith(nil))
	want := "whichports-agent version=0.1.7 vcs.revision=unknown vcs.time=unknown vcs.modified=unknown"
	if got != want {
		t.Errorf("versionLine without vcs settings:\n got %q\nwant %q", got, want)
	}
}

// An empty setting value is as absent as a missing key: unknown, not "".
func TestVersionLineEmptyValuesReadAsUnknown(t *testing.T) {
	info := buildInfoWith(map[string]string{
		"vcs.revision": "",
		"vcs.time":     "",
		"vcs.modified": "",
	})
	got := versionLine("0.1.7", info)
	if strings.Contains(got, "= ") || strings.Contains(got, "=\n") || strings.HasSuffix(got, "=") {
		t.Errorf("an empty setting leaked into the line: %q", got)
	}
	if strings.Count(got, "unknown") != 3 {
		t.Errorf("empty vcs values must all read unknown, got %q", got)
	}
}

// A build from a modified tree must say so. This is the dirty-tree mark: the
// toolchain records vcs.modified=true and the line repeats it verbatim, so a
// binary that did not come from a clean commit can never claim it did.
func TestVersionLineMarksDirtyTree(t *testing.T) {
	info := buildInfoWith(map[string]string{
		"vcs.revision": "0cd1ed220c51feba1bebc4d2102528c97027bf71",
		"vcs.time":     "2026-08-15T17:13:25Z",
		"vcs.modified": "true",
	})
	got := versionLine("0.1.6", info)
	if !strings.Contains(got, "vcs.modified=true") {
		t.Errorf("a dirty tree must be marked vcs.modified=true, got %q", got)
	}
}

// printVersion is the whole flag path after main's branch: exactly one line
// on the writer, nothing else.
func TestPrintVersionWritesExactlyOneLine(t *testing.T) {
	var buf strings.Builder
	printVersion(&buf)
	out := buf.String()
	if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
		t.Errorf("printVersion must write exactly one newline-terminated line, got %q", out)
	}
	if !strings.HasPrefix(out, "whichports-agent version=") {
		t.Errorf("the line must name the binary first, got %q", out)
	}
}

// TestVersionFileImportsOnlyHarmlessPackages is the by-construction proof
// that --version never triggers a collection. main() returns on the flag
// before run() is called, so the only code on the path is version.go, and
// this test pins that file's imports to fmt, io and runtime/debug: nothing
// that can open a file, read /proc, or reach the network. Adding such an
// import to the version path fails the suite until it is deliberately
// allowed here, the same visible act internal/safety demands.
func TestVersionFileImportsOnlyHarmlessPackages(t *testing.T) {
	allowed := map[string]bool{
		"fmt":           true,
		"io":            true,
		"runtime/debug": true,
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "version.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse version.go: %v", err)
	}
	if len(file.Imports) == 0 {
		t.Fatal("version.go has no imports, so this test is scanning the wrong file")
	}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if !allowed[path] {
			t.Errorf("version.go imports %q: the --version path must stay unable to collect, read files or touch the network", path)
		}
	}
}

// The document names the same version --version prints. These are the two
// places an operator can ask "what is running here", and them disagreeing
// would be the shape RECORD 4.85 is about: one fact, two spellings.
//
// collectDocument reads the package-level `version` the Makefile injects, so
// the test stamps it the way a build does and reads the document back.
func TestTheDocumentCarriesTheSameVersionTheFlagPrints(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })
	version = "0.1.6"

	raw, err := collectDocument(1000, "")
	if err != nil {
		t.Fatalf("collectDocument: %v", err)
	}
	var doc struct {
		AgentVersion string `json:"agent_version"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.AgentVersion != "0.1.6" {
		t.Fatalf("agent_version = %q, want 0.1.6", doc.AgentVersion)
	}
	if !strings.Contains(versionLine(version, nil), "version=0.1.6") {
		t.Fatal("--version and the document disagree about the version")
	}
}

// An unstamped build says nothing rather than shipping an empty string for a
// reader to interpret.
func TestAnUnstampedBuildLeavesTheVersionOutOfTheDocument(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })
	version = ""

	raw, err := collectDocument(1000, "")
	if err != nil {
		t.Fatalf("collectDocument: %v", err)
	}
	if strings.Contains(string(raw), "agent_version") {
		t.Fatal("an unstamped build named a version in the document")
	}
}
