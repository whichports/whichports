package collect

// Regression tests for the 2026-08-13 whole-agent review pass. Each pins one
// finding: shapes that would have made the fail-closed marshaller reject the
// whole document, or host text that bypassed sanitisation.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// A daemon response the document contract would reject (empty id,
// out-of-range port) must become the containers section's parse failure,
// never a marshal failure that costs the whole document.
func TestContainersMalformedResponseIsParseFailure(t *testing.T) {
	cases := map[string]string{
		"empty id":      `[{"Id":"","Names":["/x"],"Image":"i","Ports":[]}]`,
		"blank id":      `[{"Id":"","Names":["/x"],"Image":"i","Ports":[]}]`,
		"port too big":  `[{"Id":"abc","Names":["/x"],"Image":"i","Ports":[{"PrivatePort":80,"PublicPort":70000,"Type":"tcp"}]}]`,
		"negative port": `[{"Id":"abc","Names":["/x"],"Image":"i","Ports":[{"PrivatePort":-1,"PublicPort":8080,"Type":"tcp"}]}]`,
	}
	for name, body := range cases {
		got, verdict := queryContainers(cannedClient(200, body))
		if verdict.Status != hostdoc.StatusReadError || verdict.Cause != hostdoc.CauseParseFailed {
			t.Errorf("%s: verdict = %+v, want read_error/parse_failed", name, verdict)
		}
		if got != nil {
			t.Errorf("%s: containers returned alongside a failure: %+v", name, got)
		}
	}
}

// Zone file names come from the directory listing, and a name carrying a
// control character must not put that byte into the document's path field.
func TestMtimesHostileZoneNameSanitized(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/firewalld/zones")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ev\x1bil.xml"), []byte("<zone/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	sec := CollectRuleFileMtimes(root)
	if len(sec.Files) != 1 || sec.Files[0].Path != "/etc/firewalld/zones/ev?il.xml" {
		t.Fatalf("hostile zone path not sanitized: %+v", sec.Files)
	}
	d := hostdoc.New("h", 1)
	d.RuleFiles = sec
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, b)
}

// An unconditional underflow entry whose verdict is not a policy word must
// surface as a rule rather than vanish: the kernel should never produce it,
// and if something does, silence is the one wrong answer.
func TestLegacyOddUnderflowKeptAsRule(t *testing.T) {
	info, blob := buildFilterTable(t, func(b *blobBuilder) ([numHooks]uint32, [numHooks]uint32, uint32) {
		var hooks, under [numHooks]uint32
		e := b.add(entrySpec{targetName: "", verdict: -5}) // RETURN, not a policy
		hooks[1], under[1] = e, e
		return hooks, under, 1 << 1
	})
	table, err := parseLegacyTable(v4Parse, "filter", info, blob)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	in := table.Chains[0]
	if in.Policy != "" {
		t.Fatalf("policy = %q, want empty", in.Policy)
	}
	if len(in.Rules) != 1 || in.Rules[0].Text != "return" {
		t.Fatalf("odd underflow entry vanished: %+v", in.Rules)
	}
}
