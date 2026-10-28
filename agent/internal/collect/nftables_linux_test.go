//go:build linux

package collect

// The nftables collector's review. No live kernel: a
// fake connection feeds constructed tables, chains and rules, which makes
// every case exact and runnable in CI. The renderer's honesty grades are the
// point under test: a rule must never claim "full" unless every expression
// was understood.

import (
	"errors"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

type fakeConn struct {
	tables     []*nftables.Table
	chains     []*nftables.Chain
	rules      map[string][]*nftables.Rule // keyed by table/chain
	failTables error
	failChains error
	failRules  error

	// The sets, for the one read the collector makes of them (ctStateSet).
	// Both calls are recorded by set name, because which sets were NOT asked
	// for is half of what the tests assert.
	sets         map[string]*nftables.Set // keyed by set name
	elements     map[string][]nftables.SetElement
	failSet      error
	failElements error
	askedSets    []string
	askedElems   []string
}

func (f *fakeConn) ListTables() ([]*nftables.Table, error) {
	return f.tables, f.failTables
}
func (f *fakeConn) ListChains() ([]*nftables.Chain, error) {
	return f.chains, f.failChains
}
func (f *fakeConn) GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	if f.failRules != nil {
		return nil, f.failRules
	}
	return f.rules[t.Name+"/"+c.Name], nil
}
func (f *fakeConn) GetSetByName(t *nftables.Table, name string) (*nftables.Set, error) {
	f.askedSets = append(f.askedSets, name)
	if f.failSet != nil {
		return nil, f.failSet
	}
	return f.sets[name], nil
}
func (f *fakeConn) GetSetElements(s *nftables.Set) ([]nftables.SetElement, error) {
	f.askedElems = append(f.askedElems, s.Name)
	if f.failElements != nil {
		return nil, f.failElements
	}
	return f.elements[s.Name], nil
}

// oneChainConn wires a single inet filter/input chain carrying the given
// rules, the smallest useful ruleset shape.
func oneChainConn(rules ...*nftables.Rule) *fakeConn {
	tb := &nftables.Table{Name: "filter", Family: nftables.TableFamilyINet}
	prio := nftables.ChainPriority(0)
	pol := nftables.ChainPolicyDrop
	ch := &nftables.Chain{
		Name:     "input",
		Table:    tb,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &prio,
		Policy:   &pol,
	}
	return &fakeConn{
		tables: []*nftables.Table{tb},
		chains: []*nftables.Chain{ch},
		rules:  map[string][]*nftables.Rule{"filter/input": rules},
	}
}

func collectOne(t *testing.T, rules ...*nftables.Rule) hostdoc.NftChain {
	t.Helper()
	sec := CollectNftables(oneChainConn(rules...))
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	if len(sec.Tables) != 1 || len(sec.Tables[0].Chains) != 1 {
		t.Fatalf("want one table with one chain, got %+v", sec.Tables)
	}
	return sec.Tables[0].Chains[0]
}

func TestBaseChainProperties(t *testing.T) {
	ch := collectOne(t)
	if ch.Name != "input" || ch.Type != "filter" || ch.Hook != "input" || ch.Policy != "drop" {
		t.Fatalf("chain properties wrong: %+v", ch)
	}
	if ch.Priority == nil || *ch.Priority != 0 {
		t.Fatalf("priority wrong: %+v", ch.Priority)
	}
	sec := CollectNftables(oneChainConn())
	if sec.Tables[0].Family != "inet" {
		t.Fatalf("family = %q, want inet", sec.Tables[0].Family)
	}
}

func TestNativeRuleRendersFull(t *testing.T) {
	// The canonical "tcp dport 22 accept" as the kernel stores it: an l4proto
	// match, a transport-header dport match, a counter, a verdict.
	ch := collectOne(t, &nftables.Rule{Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x16}},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}})
	r := ch.Rules[0]
	want := "meta l4proto tcp tcp dport 22 counter accept"
	if r.Text != want || r.Rendered != "full" {
		t.Fatalf("got %q (%s), want %q (full)", r.Text, r.Rendered, want)
	}
}

func TestCtStateIdiomRendersFull(t *testing.T) {
	// ct state established,related as the kernel stores it: a state load, a
	// same-register mask of the two bits (0x02|0x04, little-endian in the
	// register), and a compare-not-zero.
	ch := collectOne(t, &nftables.Rule{Exprs: []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: []byte{0x06, 0x00, 0x00, 0x00}, Xor: []byte{0x00, 0x00, 0x00, 0x00}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x00}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}})
	r := ch.Rules[0]
	want := "ct state established,related accept"
	if r.Text != want || r.Rendered != "full" {
		t.Fatalf("got %q (%s), want %q (full)", r.Text, r.Rendered, want)
	}
}

func TestSaddrInIPv4Table(t *testing.T) {
	tb := &nftables.Table{Name: "t", Family: nftables.TableFamilyIPv4}
	ch := &nftables.Chain{Name: "c", Table: tb}
	conn := &fakeConn{
		tables: []*nftables.Table{tb},
		chains: []*nftables.Chain{ch},
		rules: map[string][]*nftables.Rule{"t/c": {{Exprs: []expr.Any{
			&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{192, 0, 2, 1}},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}}}},
	}
	sec := CollectNftables(conn)
	r := sec.Tables[0].Chains[0].Rules[0]
	if r.Text != "ip saddr 192.0.2.1 drop" || r.Rendered != "full" {
		t.Fatalf("got %q (%s)", r.Text, r.Rendered)
	}
	// The regular chain carries no base-chain fields.
	if c := sec.Tables[0].Chains[0]; c.Hook != "" || c.Policy != "" || c.Priority != nil {
		t.Fatalf("regular chain grew base-chain fields: %+v", c)
	}
}

func TestNfprotoSetsL3ContextInInet(t *testing.T) {
	// In an inet table the network header offsets are ambiguous until the
	// rule pins the IP version via meta nfproto.
	ch := collectOne(t, &nftables.Rule{Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(nftables.TableFamilyIPv4)}},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{198, 51, 100, 9}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}})
	r := ch.Rules[0]
	want := "meta nfproto ipv4 ip daddr 198.51.100.9 accept"
	if r.Text != want || r.Rendered != "full" {
		t.Fatalf("got %q (%s), want %q (full)", r.Text, r.Rendered, want)
	}
}

func TestAmbiguousNetworkPayloadStaysRaw(t *testing.T) {
	// Same load without the nfproto pin: the renderer must refuse to guess
	// the IP version and fall back to nft's exact raw form.
	ch := collectOne(t, &nftables.Rule{Exprs: []expr.Any{
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{198, 51, 100, 9}},
	}})
	r := ch.Rules[0]
	if r.Text != "@nh,128,32 0xc6336409" || r.Rendered != "full" {
		t.Fatalf("got %q (%s), want raw form, full", r.Text, r.Rendered)
	}
}

func TestXtRuleIsHonestlyPartial(t *testing.T) {
	// An iptables-nft rule (what ufw produces) carries xt match and target
	// blobs. The names are real evidence; the blob internals are not decoded
	// in v1, so the rule must grade partial, never full.
	ch := collectOne(t, &nftables.Rule{Exprs: []expr.Any{
		&expr.Match{Name: "tcp"},
		&expr.Counter{},
		&expr.Target{Name: "REJECT"},
	}})
	r := ch.Rules[0]
	want := "[xt match tcp] counter [xt target REJECT]"
	if r.Text != want || r.Rendered != "partial" {
		t.Fatalf("got %q (%s), want %q (partial)", r.Text, r.Rendered, want)
	}
}

// nftables has two rate limits that mean opposite things. `limit rate
// 10/second accept` accepts up to the rate, and `limit rate over 10/second
// accept` accepts only what is above it. Until 0.1.12 both were written as
// the one token `[limit]`, so a reader could not tell a rate-limited permit
// from a rule that permits nothing an ordinary connection sends.
func TestLimitOverIsToldApartFromLimit(t *testing.T) {
	rule := func(over bool) *nftables.Rule {
		return &nftables.Rule{Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
			&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1,
				Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x0f, 0xd2}},
			&expr.Limit{Type: expr.LimitTypePkts, Rate: 10, Unit: expr.LimitTimeSecond,
				Burst: 5, Over: over},
			&expr.Verdict{Kind: expr.VerdictAccept},
		}}
	}
	for _, tc := range []struct {
		over bool
		want string
	}{
		{false, "meta l4proto tcp tcp dport 4050 [limit] accept"},
		{true, "meta l4proto tcp tcp dport 4050 [limit over] accept"},
	} {
		r := collectOne(t, rule(tc.over)).Rules[0]
		// Partial either way: the rate and the burst are not in the text.
		if r.Text != tc.want || r.Rendered != "partial" {
			t.Errorf("over=%v: got %q (%s), want %q (partial)", tc.over, r.Text, r.Rendered, tc.want)
		}
	}
}

func TestNothingUnderstoodGradesNone(t *testing.T) {
	ch := collectOne(t, &nftables.Rule{Exprs: []expr.Any{
		&expr.Lookup{SetName: "wan_services"},
	}})
	r := ch.Rules[0]
	if r.Text != "[lookup @wan_services]" || r.Rendered != "none" {
		t.Fatalf("got %q (%s), want lookup placeholder, none", r.Text, r.Rendered)
	}
	empty := collectOne(t, &nftables.Rule{})
	if r := empty.Rules[0]; r.Text != "" || r.Rendered != "none" {
		t.Fatalf("empty rule got %q (%s), want empty, none", r.Text, r.Rendered)
	}
}

func TestRuleOrderIsPreservedNotSorted(t *testing.T) {
	// Rule order is the firewall's evaluation order. A drop-then-accept chain
	// means something different from accept-then-drop, so the collector must
	// never reorder rules, however tempting determinism-by-sorting is.
	ch := collectOne(t,
		&nftables.Rule{Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}},
		&nftables.Rule{Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}},
	)
	if ch.Rules[0].Text != "drop" || ch.Rules[1].Text != "accept" {
		t.Fatalf("rule order not preserved: %+v", ch.Rules)
	}
}

func TestTablesAndChainsSortDeterministically(t *testing.T) {
	tb1 := &nftables.Table{Name: "zz", Family: nftables.TableFamilyIPv4}
	tb2 := &nftables.Table{Name: "aa", Family: nftables.TableFamilyIPv4}
	chB := &nftables.Chain{Name: "b", Table: tb2}
	chA := &nftables.Chain{Name: "a", Table: tb2}
	conn := &fakeConn{
		tables: []*nftables.Table{tb1, tb2},
		chains: []*nftables.Chain{chB, chA},
		rules:  map[string][]*nftables.Rule{},
	}
	sec := CollectNftables(conn)
	if sec.Tables[0].Name != "aa" || sec.Tables[1].Name != "zz" {
		t.Fatalf("tables not sorted: %+v", sec.Tables)
	}
	if sec.Tables[0].Chains[0].Name != "a" || sec.Tables[0].Chains[1].Name != "b" {
		t.Fatalf("chains not sorted: %+v", sec.Tables[0].Chains)
	}
}

func TestHostileNamesAreSanitized(t *testing.T) {
	tb := &nftables.Table{Name: "ev\x1bil", Family: nftables.TableFamilyIPv4}
	ch := &nftables.Chain{Name: "ch\x07ain", Table: tb}
	conn := &fakeConn{
		tables: []*nftables.Table{tb},
		chains: []*nftables.Chain{ch},
		rules: map[string][]*nftables.Rule{"ev\x1bil/ch\x07ain": {{Exprs: []expr.Any{
			&expr.Verdict{Kind: expr.VerdictJump, Chain: "na\x1b[31msty"},
		}}}},
	}
	sec := CollectNftables(conn)
	if sec.Tables[0].Name != "ev?il" || sec.Tables[0].Chains[0].Name != "ch?ain" {
		t.Fatalf("names not sanitized: %+v", sec.Tables)
	}
	if got := sec.Tables[0].Chains[0].Rules[0].Text; got != "jump na?[31msty" {
		t.Fatalf("verdict chain not sanitized: %q", got)
	}
	d := hostdoc.New("h", 1)
	d.Nftables = sec
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, b)
}

func TestUnknownFamilyIsUnknownNotInvented(t *testing.T) {
	tb := &nftables.Table{Name: "t", Family: nftables.TableFamily(99)}
	conn := &fakeConn{tables: []*nftables.Table{tb}}
	sec := CollectNftables(conn)
	if sec.Tables[0].Family != "unknown" {
		t.Fatalf("family = %q, want unknown", sec.Tables[0].Family)
	}
	d := hostdoc.New("h", 1)
	d.Nftables = sec
	if _, err := hostdoc.Marshal(d); err != nil {
		t.Fatalf("unknown family must still pass the contract: %v", err)
	}
}

func TestRuleCommentSurvivesSanitized(t *testing.T) {
	// Userdata TLV, type 0, NUL-terminated: the comment the admin wrote.
	ud := []byte{0x00, 0x05, 'h', 'i', '\x1b', '!', 0x00}
	ch := collectOne(t, &nftables.Rule{
		Exprs:    []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
		UserData: ud,
	})
	if got := ch.Rules[0].Comment; got != "hi?!" {
		t.Fatalf("comment = %q, want hi?!", got)
	}
	// Truncated TLV yields no comment, never a crash.
	ch2 := collectOne(t, &nftables.Rule{
		Exprs:    []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
		UserData: []byte{0x00, 0xFF, 'x'},
	})
	if ch2.Rules[0].Comment != "" {
		t.Fatalf("truncated TLV produced comment %q", ch2.Rules[0].Comment)
	}
}

func TestNetlinkFailuresAreTyped(t *testing.T) {
	// syscall.EPERM is exactly what netlink returns to an unprivileged
	// reader, and errors.Is maps it to os.ErrPermission.
	permission := &fakeConn{failTables: syscall.EPERM}
	if sec := CollectNftables(permission); sec.Status != hostdoc.StatusPermissionDenied || sec.Cause != hostdoc.CausePermission {
		t.Fatalf("permission failure mis-typed: %+v", sec.Section)
	}
	broken := oneChainConn()
	broken.failRules = errors.New("netlink: interrupted dump")
	if sec := CollectNftables(broken); sec.Status != hostdoc.StatusReadError || sec.Cause != hostdoc.CauseNetlink {
		t.Fatalf("rules failure mis-typed: %+v", sec.Section)
	}
	if sec := CollectNftables(broken); len(sec.Tables) != 0 {
		t.Fatal("a failed section must not carry a truncated ruleset")
	}
}

func TestEmptyRulesetIsCollected(t *testing.T) {
	sec := CollectNftables(&fakeConn{})
	if sec.Status != hostdoc.StatusCollected || len(sec.Tables) != 0 {
		t.Fatalf("empty ruleset: status=%q tables=%d, want collected/0", sec.Status, len(sec.Tables))
	}
}

func TestUnknownExprInvalidatesRegisterContext(t *testing.T) {
	// Found live on an AlmaLinux 10 server: firewalld's rpfilter rule loads a fib route
	// check into the register a meta nfproto match had used. The renderer
	// must not reuse the stale context and print "meta nfproto 0" as if it
	// understood the comparison; it must fall back.
	ch := collectOne(t, &nftables.Rule{Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(nftables.TableFamilyIPv6)}},
		&expr.Fib{Register: 1, ResultADDRTYPE: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}})
	r := ch.Rules[0]
	want := "meta nfproto ipv6 [expr Fib] [cmp on unknown register] drop"
	if r.Text != want || r.Rendered != "partial" {
		t.Fatalf("got %q (%s), want %q (partial)", r.Text, r.Rendered, want)
	}
}

func TestPortRangeRendersBothBounds(t *testing.T) {
	// A dport range arrives as two comparisons on the same register.
	ch := collectOne(t, &nftables.Rule{Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: []byte{0x00, 0x64}},
		&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: []byte{0x00, 0xC8}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}})
	r := ch.Rules[0]
	want := "meta l4proto udp udp dport >= 100 udp dport <= 200 accept"
	if r.Text != want || r.Rendered != "full" {
		t.Fatalf("got %q (%s), want %q (full)", r.Text, r.Rendered, want)
	}
}

func TestIfnameRendersTrimmedAndQuoted(t *testing.T) {
	// Interface names arrive NUL-padded to their fixed width.
	ch := collectOne(t, &nftables.Rule{Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{'e', 't', 'h', '0', 0, 0, 0, 0}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}})
	r := ch.Rules[0]
	want := `iifname "eth0" accept`
	if r.Text != want || r.Rendered != "full" {
		t.Fatalf("got %q (%s), want %q (full)", r.Text, r.Rendered, want)
	}
}
