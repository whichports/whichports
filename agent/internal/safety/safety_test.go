package safety

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests are the enforcement. They scan the agent's own source and fail
// the build if a forbidden capability appears anywhere in it. This is how the
// security boundary stays real as the code grows: adding an exec call, a
// listening socket or a firewall write does not just violate a comment, it
// breaks the suite.
//
// Two properties matter as much as the scan itself, and each has its own test
// below. First, the scan reads the manifest in safety.go rather than a second
// copy of the same list, so the two cannot drift apart. Second, the scan is
// itself tested against source that does break the rules, because a scanner
// that silently matches nothing would pass every run and protect nothing.

// agentRoot walks up from this test file to the agent module root (the dir with
// go.mod), so the scan covers every package under the agent.
func agentRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find agent module root (go.mod)")
		}
		dir = parent
	}
}

// goFiles returns every non-test .go file under root. Test files are excluded
// because this very file names the forbidden symbols in string literals, and
// the point is to scan production code.
// The one directory under the agent root that is not agent code. Named here so
// the walk compares a path rather than a name, and so a test can assert it was
// actually found: a skip rule for a directory that has moved is a rule that
// silently stops skipping, and a skip rule that matches more than it should is
// how a whole package hides.
const skippedDir = "reference"

func goFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	var skipped []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// `agent/reference` holds recon.sh notes, not agent code
			// **One exact directory, not any directory with
			// that name.**
			//
			// This was `info.Name() == "reference"`, a basename compare that
			// skipped a directory called `reference` at any depth. A real
			// compiled package at `internal/collect/reference/` was therefore
			// invisible to all three scans at once, and an adversarial review
			// on 2026-08-22 built one that opened a listener and started a
			// process with the suite staying green. `docs/RECORD.md` 4.94.
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil && rel == skippedDir {
				skipped = append(skipped, rel)
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The skip is only safe if it is doing what it says. A rule that matched
	// nothing means the directory moved and the exclusion is now silently
	// dead, which is fine, and a rule that matched twice means the compare is
	// too loose again, which is the fault this replaced.
	if len(skipped) > 1 {
		t.Fatalf("the reference skip matched %v, and it may only ever match one directory", skipped)
	}
	return files
}

// bannedCalls builds the scanner's lookup from the manifest in safety.go.
// Building it here rather than restating the names is the whole point: a
// symbol added to the manifest is enforced from that moment, and a symbol
// deleted from the manifest is a visible, reviewable act.
func bannedCalls() map[string]string {
	banned := map[string]string{}
	for _, s := range ForbiddenListenSymbols {
		banned[s] = "SI-1, the agent has no listening socket"
	}
	for _, s := range ForbiddenExecSymbols {
		banned[s] = "SI-4, the agent executes nothing"
	}
	for _, s := range ForbiddenDialSymbols {
		// Bare dials and the package-level HTTP client are banned everywhere,
		// including the HTTP-capable files: the declared network paths build
		// their clients explicitly, with the TLS floor and the no-redirect
		// policy, and these helpers would bypass exactly that (PRODUCT.md 4f).
		banned[s] = "network confinement, PRODUCT.md 4f"
	}
	return banned
}

// bannedWriteMethods builds the SI-3 lookup from the manifest in safety.go,
// under the same single-source rule as bannedCalls: the test reads the
// manifest, it never restates it.
func bannedWriteMethods() map[string]string {
	banned := map[string]string{}
	for _, s := range ForbiddenNftWriteSymbols {
		banned[s] = "SI-3, the agent is read only and cannot edit a firewall rule"
	}
	return banned
}

// importNames maps the identifier a file actually writes to the package name
// the banned list is written in.
//
// This exists because the scan used to compare the identifier in the source
// directly, so renaming an import walked straight past it: `import sysos "os"`
// followed by `sysos.StartProcess(...)` never matched "os.StartProcess", the
// binary started a process, and the boundary test stayed green. It needs a
// commit rather than hostile input, and a diff renaming an import to sysos
// would look odd to a reviewer. The design rule here is that it must not
// matter whether that reviewer catches a subtle thing, and this is exactly
// a thing that survives review.
//
// A dot import is reported rather than resolved: it puts the package's names
// into file scope with no qualifier at all, so there is no selector left to
// match. The agent has no dot imports and no reason to gain one.
func importNames(file *ast.File) (map[string]string, []string) {
	names := map[string]string{}
	var dotImports []string
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		// The name a package has by default is the last element of its path:
		// "os/exec" is exec, "golang.org/x/sys/unix" is unix.
		def := path
		if i := strings.LastIndex(def, "/"); i >= 0 {
			def = def[i+1:]
		}
		local := def
		if spec.Name != nil {
			local = spec.Name.Name
		}
		switch local {
		case ".":
			dotImports = append(dotImports, path)
		case "_":
			// Imported for its side effects, nothing to call through it.
		default:
			names[local] = def
		}
	}
	return names, dotImports
}

// findForbiddenCalls parses one Go source and returns every banned
// package-qualified name it uses, resolved through the file's imports so an
// alias cannot hide one. Splitting this out of the tree walk is what lets
// TestScannerCatchesForbiddenCalls feed it deliberately bad source.
func findForbiddenCalls(t *testing.T, filename string, src []byte, banned map[string]string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	names, dotImports := importNames(file)
	var found []string
	for _, path := range dotImports {
		// No qualifier survives a dot import, so the only honest thing the
		// scan can say is that it can no longer see.
		found = append(found, "dot import of "+path+", which this scan cannot see through")
	}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		// Only a qualifier this file actually imports can be a package. A
		// selector on anything else is a field or a method on a value, and
		// matching those produced false alarms: a local variable named `exec`
		// with a `Command` field read exactly like os/exec.Command.
		//
		// Skipping them loses no coverage. Go has no way to name a package
		// without importing it, so code that compiles and calls a forbidden
		// symbol has the import, and the import is what this resolves.
		qualifier, imported := names[pkg.Name]
		if !imported {
			return true
		}
		name := qualifier + "." + sel.Sel.Name
		if _, bad := banned[name]; bad {
			found = append(found, name)
		}
		return true
	})
	return found
}

// findForbiddenMethodCalls parses one Go source and returns every selector
// whose member name is in the banned set, whatever the receiver is. It is
// deliberately blunter than findForbiddenCalls, and the difference is the
// point: a ruleset write is a method on a Conn value, a method call carries
// no package qualifier, and an AST scan cannot know a variable's type, so
// the method name is all there is to match. Matching it on any receiver also
// closes the obvious evasion. A Conn handed out by a helper reaches a file
// that never imports nftables, and a method keeps its receiver whatever the
// imports say, so there is no alias or dot-import hole to see through here.
//
// The precision worry that shaped findForbiddenCalls does not bite. The
// manifest names are distinctive, no agent code calls a method or reads a
// field with any of these names on any type, which was checked when the list
// landed, and a future false positive fails the suite loudly where a person
// resolves it. A false negative would be a silent hole in SI-3, which is the
// worse trade in both directions.
func findForbiddenMethodCalls(t *testing.T, filename string, src []byte, banned map[string]string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if _, bad := banned[sel.Sel.Name]; bad {
			found = append(found, sel.Sel.Name)
		}
		return true
	})
	return found
}

// findImports returns the import paths of one Go source.
func findImports(t *testing.T, filename string, src []byte) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	var out []string
	for _, imp := range file.Imports {
		out = append(out, strings.Trim(imp.Path.Value, `"`))
	}
	return out
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func TestNoForbiddenImports(t *testing.T) {
	root := agentRoot(t)
	forbidden := map[string]bool{}
	for _, p := range ForbiddenImports {
		forbidden[p] = true
	}
	for _, f := range goFiles(t, root) {
		for _, path := range findImports(t, f, readFile(t, f)) {
			if forbidden[path] {
				t.Errorf("%s imports %s, forbidden by safety.ForbiddenImports (SI-4 and the no-exec read decision, PRODUCT.md 4e)", f, path)
			}
		}
	}
}

// TestNoForbiddenCalls scans the full AST for calls that would open a listening
// socket, exec a process, or dial outside the two declared network paths. It
// catches, for example, os.StartProcess, which needs no os/exec import and so
// slips past the import check entirely.
func TestNoForbiddenCalls(t *testing.T) {
	root := agentRoot(t)
	banned := bannedCalls()
	for _, f := range goFiles(t, root) {
		for _, name := range findForbiddenCalls(t, f, readFile(t, f), banned) {
			t.Errorf("%s uses %s, forbidden by %s", f, name, banned[name])
		}
	}
}

// TestNoNftablesWrites is SI-3 made mechanical. The nftables collector holds
// a live netlink connection, and the same Conn that lists the ruleset can
// rewrite it: the write methods sit as close to the collector's code as the
// read methods it uses, and sandboxing does not stand in the way because the
// ruleset is written over netlink, which CAP_NET_ADMIN grants, not through
// the filesystem that ProtectSystem=strict covers. So the absence of writes
// is enforced by scan, exactly like SI-1 and SI-4, rather than trusted to
// review.
func TestNoNftablesWrites(t *testing.T) {
	root := agentRoot(t)
	banned := bannedWriteMethods()
	for _, f := range goFiles(t, root) {
		for _, name := range findForbiddenMethodCalls(t, f, readFile(t, f), banned) {
			t.Errorf("%s calls %s, forbidden by %s", f, name, banned[name])
		}
	}
}

// TestScannerCatchesNftablesWrites is the test of the test, the same posture
// as TestScannerCatchesForbiddenCalls below: every write method in the
// manifest is fed to the scanner inside source that really does use it, and
// must be flagged, or the SI-3 scan could rot into matching nothing.
func TestScannerCatchesNftablesWrites(t *testing.T) {
	banned := bannedWriteMethods()
	if len(banned) == 0 {
		t.Fatal("the SI-3 manifest is empty, so the scan enforces nothing")
	}
	for name := range banned {
		// Written as a method value rather than a call so one source shape
		// works for every signature in the manifest.
		src := fmt.Sprintf("package p\n\nimport \"github.com/google/nftables\"\n\nfunc f(c *nftables.Conn) { _ = c.%s }\n", name)
		found := findForbiddenMethodCalls(t, "synthetic.go", []byte(src), banned)
		if len(found) != 1 || found[0] != name {
			t.Errorf("the scanner missed %s: it would not fail the build if the agent used it", name)
		}
	}
}

// A Conn that arrives through a helper needs no nftables import in the file
// that misuses it, so the write scan must not depend on imports at all. This
// is the method-call analogue of the aliased-import hole further down.
func TestNftablesWriteScanNeedsNoImport(t *testing.T) {
	src := `package p

import "example.com/agent/internal/collect"

func f() error {
	c := collect.LiveConn()
	c.FlushRuleset()
	return c.Flush()
}
`
	found := findForbiddenMethodCalls(t, "mutant.go", []byte(src), bannedWriteMethods())
	if len(found) != 2 {
		t.Fatalf("expected both write calls flagged in a file with no nftables import, got %v", found)
	}
}

// And the collector's reads must pass, or the scan would flag the one file it
// exists to police. The shape mirrors internal/collect/nftables_linux.go,
// and TestNoNftablesWrites scanning the real tree is what proves the real
// collector passes too.
func TestNftablesWriteScanAcceptsTheCollector(t *testing.T) {
	src := `package p

import "github.com/google/nftables"

func f() error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	chains, err := conn.ListChains()
	if err != nil {
		return err
	}
	for _, tb := range tables {
		for _, ch := range chains {
			if _, err := conn.GetRules(tb, ch); err != nil {
				return err
			}
		}
	}
	return nil
}
`
	if found := findForbiddenMethodCalls(t, "clean.go", []byte(src), bannedWriteMethods()); len(found) != 0 {
		t.Fatalf("the collector's reads were flagged: %v", found)
	}
}

// TestScannerCatchesForbiddenCalls is the test of the test. Every symbol in
// the manifest is fed to the scanner inside source that really does use it,
// and must be flagged. Without this, a scanner that matched nothing at all
// would pass TestNoForbiddenCalls on every run while enforcing nothing, and
// nobody would find out until the boundary had already been crossed.
func TestScannerCatchesForbiddenCalls(t *testing.T) {
	banned := bannedCalls()
	if len(banned) == 0 {
		t.Fatal("the manifest is empty, so the scan enforces nothing")
	}
	for name := range banned {
		pkg, sym, ok := strings.Cut(name, ".")
		if !ok {
			t.Errorf("manifest entry %q is not package.Symbol", name)
			continue
		}
		// Written as a plain reference rather than a call so the same source
		// shape works for functions and for types like net.ListenConfig.
		src := fmt.Sprintf("package p\n\nimport %q\n\nvar _ = %s.%s\n", pkg, pkg, sym)
		found := findForbiddenCalls(t, "synthetic.go", []byte(src), banned)
		if len(found) != 1 || found[0] != name {
			t.Errorf("the scanner missed %s: it would not fail the build if the agent used it", name)
		}
	}
}

// TestScannerAcceptsCleanSource is the other half: the scanner must not flag
// source that keeps the rules, or the suite would be noise everyone learns to
// ignore.
func TestScannerAcceptsCleanSource(t *testing.T) {
	src := `package p

import (
	"net/http"
	"os"
)

func f(c *http.Client) { _, _ = c.Get("http://unix/x") }
func g() { _, _ = os.ReadFile("/proc/net/tcp") }
`
	if found := findForbiddenCalls(t, "clean.go", []byte(src), bannedCalls()); len(found) != 0 {
		t.Errorf("clean source was flagged: %v", found)
	}
}

// TestHTTPImportsAreConfined keeps network capability where it was declared:
// only the files listed in HTTPCapableFiles may import net/http. It also
// fails when a listed file disappears, so the manifest cannot rot into an
// allowlist of nothing.
func TestHTTPImportsAreConfined(t *testing.T) {
	root := agentRoot(t)
	allowed := map[string]bool{}
	for _, rel := range HTTPCapableFiles {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if _, err := os.Stat(abs); err != nil {
			t.Errorf("safety.HTTPCapableFiles lists %s which does not exist, update the manifest", rel)
		}
		allowed[abs] = true
	}
	for _, f := range goFiles(t, root) {
		for _, path := range findImports(t, f, readFile(t, f)) {
			if path == "net/http" && !allowed[f] {
				t.Errorf("%s imports net/http but is not declared in safety.HTTPCapableFiles: network capability stays where it is declared and reviewed", f)
			}
		}
	}
}

// TestReportPackageParsesNoResponse is SI-2 made mechanical. PRODUCT.md 4f
// claims the agent has no response-parsing code at all, which is a stronger
// and more auditable claim than "the response parser is safe". This test is
// what keeps the claim true: the package that talks to the control plane may
// not import a decoder and may not read a body into memory. It drains into
// io.Discard and reads the status code, and that is all it can do.
func TestReportPackageParsesNoResponse(t *testing.T) {
	root := agentRoot(t)
	dir := filepath.Join(root, filepath.FromSlash(ResponseParsingBannedIn))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v (the manifest names a package that is not there)", dir, err)
	}

	forbiddenImport := map[string]bool{}
	for _, p := range ForbiddenDecoderImports {
		forbiddenImport[p] = true
	}
	bannedRead := map[string]string{}
	for _, s := range ForbiddenBodyReadSymbols {
		bannedRead[s] = "SI-2, the response body is drained, never read into memory"
	}

	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		path := filepath.Join(dir, name)
		src := readFile(t, path)
		for _, imp := range findImports(t, path, src) {
			if forbiddenImport[imp] {
				t.Errorf("%s imports %s: %s may not decode anything the control plane sends (SI-2, PRODUCT.md 4f)", path, imp, ResponseParsingBannedIn)
			}
		}
		for _, sym := range findForbiddenCalls(t, path, src, bannedRead) {
			t.Errorf("%s calls %s, forbidden by %s", path, sym, bannedRead[sym])
		}
	}
	if scanned == 0 {
		t.Fatalf("scanned no files in %s, so this test proves nothing", dir)
	}
}

// TestInvariantsCoverAllSI guards that the in-code manifest still lists all
// eight invariants. If the project gains an SI-9, this fails until it is added
// here too, so the manifest cannot silently fall behind the document.
func TestInvariantsCoverAllSI(t *testing.T) {
	want := map[string]bool{
		"SI-1": false, "SI-2": false, "SI-3": false, "SI-4": false,
		"SI-5": false, "SI-6": false, "SI-7": false, "SI-8": false,
	}
	for _, inv := range Invariants {
		if _, known := want[inv.ID]; !known {
			t.Errorf("unexpected invariant %s, update this test if the project added it", inv.ID)
		}
		want[inv.ID] = true
		if strings.TrimSpace(inv.Rule) == "" {
			t.Errorf("%s has an empty rule", inv.ID)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("%s is missing from the manifest", id)
		}
	}
}

// An aliased import must not hide a forbidden call.
//
// This is a regression test for a real hole. The scan compared the identifier
// written in the source, so `import sysos "os"` then `sysos.StartProcess(...)`
// matched nothing. It compiled, it started a process, and this suite stayed
// green. Reproduced by mutation on 2026-08-21 before it was fixed.
func TestScannerSeesThroughAnAliasedImport(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"aliased os", `package p

import sysos "os"

func f() { _, _ = sysos.StartProcess("/bin/sh", nil, nil) }
`},
		{"aliased os/exec", `package p

import run "os/exec"

func f() { _ = run.Command("/bin/sh") }
`},
		{"alias that impersonates another package", `package p

import exec "os"

func f() { _, _ = exec.StartProcess("/bin/sh", nil, nil) }
`},
		{"aliased net", `package p

import n "net"

func f() { _, _ = n.Listen("tcp", ":0") }
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found := findForbiddenCalls(t, "mutant.go", []byte(tc.src), bannedCalls())
			if len(found) == 0 {
				t.Fatal("an aliased import hid a forbidden call from the scan")
			}
		})
	}
}

// A dot import removes the qualifier entirely, so there is no selector left to
// match. The scan says so rather than reporting nothing and looking clean.
func TestScannerRefusesADotImport(t *testing.T) {
	src := `package p

import . "os"

func f() { _, _ = StartProcess("/bin/sh", nil, nil) }
`
	found := findForbiddenCalls(t, "mutant.go", []byte(src), bannedCalls())
	if len(found) == 0 {
		t.Fatal("a dot import hid a forbidden call from the scan")
	}
}

// And the resolution must not invent findings. A local variable or a field
// that happens to share a package's name is not a package.
func TestScannerDoesNotFlagANonPackageIdentifier(t *testing.T) {
	src := `package p

type thing struct{ Command string }

func f() {
	exec := thing{Command: "not a call"}
	_ = exec.Command
}
`
	if found := findForbiddenCalls(t, "clean.go", []byte(src), bannedCalls()); len(found) != 0 {
		t.Fatalf("flagged a non-package identifier: %v", found)
	}
}
