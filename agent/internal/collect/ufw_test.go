package collect

// The ufw collector's review. Fixtures under testdata/fsroots: ubuntu-ufw is
// modelled line for line on /etc/ufw and /etc/default/ufw captured from the
// Ubuntu 26.04 prod box on 2026-08-12 (rules: limit 22, allow 80, allow 443,
// which RECORD.md 4.12 and 4.16 already describe publicly). alma-firewalld
// has no ufw at all, and hostile carries a binary conf plus a tuple with a
// terminal escape in it.

import (
	"bytes"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

func TestUfwUbuntuProfile(t *testing.T) {
	sec := CollectUfw("testdata/fsroots/ubuntu-ufw")
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	for _, src := range hostdoc.UfwSources {
		if sec.Sources[src].Status != hostdoc.StatusCollected {
			t.Fatalf("source %s = %+v, want collected", src, sec.Sources[src])
		}
	}
	if sec.Conf["ENABLED"] != "yes" || sec.Conf["LOGLEVEL"] != "low" {
		t.Fatalf("conf wrong: %v", sec.Conf)
	}
	// The quotes around the policy values must be stripped, and the forward
	// policy must be present: ufw filters forwarded traffic too, and losing
	// that key would repeat the retracted INPUT-only claim (PRODUCT.md 4b).
	if sec.Defaults["DEFAULT_INPUT_POLICY"] != "DROP" ||
		sec.Defaults["DEFAULT_FORWARD_POLICY"] != "DROP" ||
		sec.Defaults["DEFAULT_OUTPUT_POLICY"] != "ACCEPT" ||
		sec.Defaults["IPV6"] != "yes" {
		t.Fatalf("defaults wrong: %v", sec.Defaults)
	}
	// The empty quoted value stays present as an empty string, not dropped:
	// "the key is set to nothing" and "the key is absent" differ.
	if v, ok := sec.Defaults["IPT_MODULES"]; !ok || v != "" {
		t.Fatalf("IPT_MODULES = %q present=%v, want empty and present", v, ok)
	}
	wantRules := []string{
		"limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",
		"allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in",
		"allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in",
	}
	wantRules6 := []string{
		"limit tcp 22 ::/0 any ::/0 in",
		"allow tcp 80 ::/0 any ::/0 in",
		"allow tcp 443 ::/0 any ::/0 in",
	}
	assertStrings(t, "rules", sec.Rules, wantRules)
	assertStrings(t, "rules6", sec.Rules6, wantRules6)
}

func TestUfwAbsentIsNotPresent(t *testing.T) {
	sec := CollectUfw("testdata/fsroots/alma-firewalld")
	if sec.Status != hostdoc.StatusNotPresent {
		t.Fatalf("status = %q, want not_present", sec.Status)
	}
	for _, src := range hostdoc.UfwSources {
		if sec.Sources[src].Status != hostdoc.StatusNotPresent {
			t.Fatalf("source %s = %+v, want not_present", src, sec.Sources[src])
		}
	}
}

func TestUfwHostileProfile(t *testing.T) {
	sec := CollectUfw("testdata/fsroots/hostile")
	// The binary conf is a parse failure, named per source, while the
	// readable rules file keeps the section collected.
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	if got := sec.Sources["ufw.conf"]; got.Status != hostdoc.StatusReadError || got.Cause != hostdoc.CauseParseFailed {
		t.Fatalf("ufw.conf verdict = %+v, want read_error/parse_failed", got)
	}
	if len(sec.Rules) != 1 || sec.Rules[0] != "allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in ?[31mevil" {
		t.Fatalf("hostile tuple not sanitized as expected: %q", sec.Rules)
	}

	d := hostdoc.New("h", 1)
	d.Ufw = sec
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, b)
	if bytes.ContainsRune(b, 0x1b) {
		t.Fatal("escape byte reached the document")
	}
}

func TestUfwDeterministic(t *testing.T) {
	d1 := hostdoc.New("h", 1)
	d1.Ufw = CollectUfw("testdata/fsroots/ubuntu-ufw")
	d2 := hostdoc.New("h", 1)
	d2.Ufw = CollectUfw("testdata/fsroots/ubuntu-ufw")
	b1, err1 := hostdoc.Marshal(d1)
	b2, err2 := hostdoc.Marshal(d2)
	if err1 != nil || err2 != nil {
		t.Fatalf("marshal errors: %v %v", err1, err2)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("two collections of the same ufw state differ")
	}
}

// TestAggregateSourcesPrecedence pins the shared aggregation rule directly:
// permission outranks parse failure when nothing collected, and one healthy
// source wins over both.
func TestAggregateSourcesPrecedence(t *testing.T) {
	perm := hostdoc.Section{Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission}
	parse := hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	ok := hostdoc.Section{Status: hostdoc.StatusCollected}
	absent := hostdoc.Section{Status: hostdoc.StatusNotPresent}

	cases := []struct {
		name string
		in   map[string]hostdoc.Section
		want hostdoc.SectionStatus
	}{
		{"one healthy wins", map[string]hostdoc.Section{"a": ok, "b": perm, "c": parse}, hostdoc.StatusCollected},
		{"perm beats parse", map[string]hostdoc.Section{"a": perm, "b": parse}, hostdoc.StatusPermissionDenied},
		{"parse alone", map[string]hostdoc.Section{"a": parse, "b": absent}, hostdoc.StatusReadError},
		{"all absent", map[string]hostdoc.Section{"a": absent, "b": absent}, hostdoc.StatusNotPresent},
	}
	for _, c := range cases {
		if got := aggregateSources(c.in); got.Status != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got.Status, c.want)
		}
	}
}

func assertStrings(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %q, want %q", what, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %q, want %q", what, i, got[i], want[i])
		}
	}
}
