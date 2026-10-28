//go:build linux

package collect

// A conntrack state looked up in an anonymous set, which is how firewalld
// 0.9.11 on the RHEL 8 family writes every port it opens:
//
//	tcp dport 6000 ct state { new, untracked } accept
//
// Until 0.1.12 the agent wrote that as `... [lookup @__set0] accept`, with the
// words "ct state" gone, so nothing reading the document could tell it from a
// rule open to a list of addresses, and every such port read as having no
// rule (docs/RECORD.md 4.220).
//
// The expressions and the set below are what nft sends the kernel for that
// line, read with `nft --debug=netlink` on nftables 1.1.3 on 2026-10-02:
//
//	[ meta load l4proto => reg 1 ]
//	[ cmp eq reg 1 0x00000006 ]
//	[ payload load 2b @ transport header + 2 => reg 1 ]
//	[ cmp eq reg 1 0x00007017 ]
//	[ ct load state => reg 1 ]
//	[ lookup reg 1 set __set%d ]
//	[ immediate reg 0 accept ]
//	__set%d wptest 3      element 00000008  element 00000040
//
// Read on RHEL 8's family as well, the same day: Rocky Linux 8.10, kernel
// 4.18, nftables 1.0.4, firewalld 0.9.11, a port opened with firewall-cmd. The
// agent wrote the rule as the first test below expects, graded full, as root
// and under its unit (docs/RECORD.md 4.246).

import (
	"errors"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// The five states as the kernel stores one in a register, little-endian.
var (
	stateInvalid     = []byte{0x01, 0x00, 0x00, 0x00}
	stateEstablished = []byte{0x02, 0x00, 0x00, 0x00}
	stateRelated     = []byte{0x04, 0x00, 0x00, 0x00}
	stateNew         = []byte{0x08, 0x00, 0x00, 0x00}
	stateUntracked   = []byte{0x40, 0x00, 0x00, 0x00}
)

// portThenStateLookup is `tcp dport 6000 ct state <lookup in set> accept`.
func portThenStateLookup(setName string, invert bool) *nftables.Rule {
	return &nftables.Rule{Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1,
			Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x17, 0x70}},
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: setName, Invert: invert},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}}
}

// anonymousSet is the inline `{ ... }` form: anonymous and constant.
func anonymousSet(name string) *nftables.Set {
	return &nftables.Set{Name: name, Anonymous: true, Constant: true}
}

func keys(states ...[]byte) []nftables.SetElement {
	var out []nftables.SetElement
	for _, state := range states {
		out = append(out, nftables.SetElement{Key: state})
	}
	return out
}

// collectWithSets runs the collector over one chain holding rule, against a
// connection that has the given sets, and returns the rule and the
// connection, so a test can read what was asked of it.
func collectWithSets(t *testing.T, rule *nftables.Rule, sets map[string]*nftables.Set,
	elements map[string][]nftables.SetElement) (hostdoc.NftRule, *fakeConn) {
	t.Helper()
	conn := oneChainConn(rule)
	conn.sets = sets
	conn.elements = elements
	sec := CollectNftables(conn)
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	return sec.Tables[0].Chains[0].Rules[0], conn
}

func TestFirewalldsNewAndUntrackedSetRendersAsNftPrintsIt(t *testing.T) {
	r, _ := collectWithSets(t, portThenStateLookup("__set0", false),
		map[string]*nftables.Set{"__set0": anonymousSet("__set0")},
		map[string][]nftables.SetElement{"__set0": keys(stateNew, stateUntracked)})
	want := "meta l4proto tcp tcp dport 6000 ct state { new, untracked } accept"
	if r.Text != want || r.Rendered != "full" {
		t.Fatalf("got %q (%s), want %q (full)", r.Text, r.Rendered, want)
	}
}

func TestCtStateSetShapes(t *testing.T) {
	cases := []struct {
		name   string
		invert bool
		keys   []nftables.SetElement
		want   string
	}{
		// The kernel hands a hash set's elements back in no promised order,
		// and two collections of one ruleset must read the same.
		{"the elements the other way round", false, keys(stateUntracked, stateNew),
			"ct state { new, untracked }"},
		{"one state", false, keys(stateNew), "ct state { new }"},
		{"the replies, which open nothing to a first packet", false,
			keys(stateRelated, stateEstablished), "ct state { established, related }"},
		{"all five", false, keys(stateUntracked, stateNew, stateRelated, stateEstablished, stateInvalid),
			"ct state { invalid, established, related, new, untracked }"},
		{"an element given twice", false, keys(stateNew, stateNew), "ct state { new }"},
		{"an inverted lookup", true, keys(stateNew, stateUntracked),
			"ct state != { new, untracked }"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := collectWithSets(t, portThenStateLookup("__set0", tc.invert),
				map[string]*nftables.Set{"__set0": anonymousSet("__set0")},
				map[string][]nftables.SetElement{"__set0": tc.keys})
			want := "meta l4proto tcp tcp dport 6000 " + tc.want + " accept"
			if r.Text != want || r.Rendered != "full" {
				t.Fatalf("got %q (%s), want %q (full)", r.Text, r.Rendered, want)
			}
		})
	}
}

// Everything the renderer cannot name exactly stays the bracket it was, and
// the rule stays graded partial. A list with one name missing would read as
// a shorter list, which is a different rule.
func TestCtStateSetThatCannotBeNamedStaysABracket(t *testing.T) {
	const bracket = "meta l4proto tcp tcp dport 6000 [lookup @__set0] accept"
	interval := anonymousSet("__set0")
	interval.Interval = true
	mapSet := anonymousSet("__set0")
	mapSet.IsMap = true
	concatenated := anonymousSet("__set0")
	concatenated.Concatenation = true

	cases := []struct {
		name string
		set  *nftables.Set
		keys []nftables.SetElement
	}{
		{"a bit nobody defined", anonymousSet("__set0"),
			keys(stateNew, []byte{0x80, 0x00, 0x00, 0x00})},
		{"the reply-direction bit, which is no state of its own", anonymousSet("__set0"),
			keys(stateNew, []byte{0x10, 0x00, 0x00, 0x00})},
		{"one element that is two states at once", anonymousSet("__set0"),
			keys([]byte{0x48, 0x00, 0x00, 0x00})},
		{"zero", anonymousSet("__set0"), keys([]byte{0x00, 0x00, 0x00, 0x00})},
		{"an element of two bytes", anonymousSet("__set0"), keys([]byte{0x08, 0x00})},
		{"an element of eight bytes", anonymousSet("__set0"),
			keys([]byte{0x08, 0, 0, 0, 0, 0, 0, 0})},
		{"an element with no key", anonymousSet("__set0"), []nftables.SetElement{{}}},
		{"an interval end", anonymousSet("__set0"),
			[]nftables.SetElement{{Key: stateNew}, {Key: stateUntracked, IntervalEnd: true}}},
		{"an empty set", anonymousSet("__set0"), nil},
		{"an interval set", interval, keys(stateNew)},
		{"a map", mapSet, keys(stateNew)},
		{"a concatenation", concatenated, keys(stateNew)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := collectWithSets(t, portThenStateLookup("__set0", false),
				map[string]*nftables.Set{"__set0": tc.set},
				map[string][]nftables.SetElement{"__set0": tc.keys})
			if r.Text != bracket || r.Rendered != "partial" {
				t.Fatalf("got %q (%s), want %q (partial)", r.Text, r.Rendered, bracket)
			}
		})
	}
}

// A set that cannot be read costs that one rule its states and nothing else:
// the section is still collected, the rule is still there, graded partial.
// Failing the whole section over it would lose every rule on the host for a
// detail of one.
func TestCtStateSetThatCannotBeReadStaysABracket(t *testing.T) {
	const bracket = "meta l4proto tcp tcp dport 6000 [lookup @__set0] accept"
	cases := []struct {
		name  string
		shape func(*fakeConn)
	}{
		{"the set lookup is refused", func(f *fakeConn) { f.failSet = syscall.EPERM }},
		{"the set lookup fails", func(f *fakeConn) { f.failSet = errors.New("netlink receive: timeout") }},
		{"the kernel has no set of that name", func(f *fakeConn) { f.sets = nil }},
		{"the element read is refused", func(f *fakeConn) { f.failElements = syscall.EPERM }},
		{"the element read fails", func(f *fakeConn) { f.failElements = syscall.ENOENT }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := oneChainConn(portThenStateLookup("__set0", false))
			conn.sets = map[string]*nftables.Set{"__set0": anonymousSet("__set0")}
			conn.elements = map[string][]nftables.SetElement{"__set0": keys(stateNew, stateUntracked)}
			tc.shape(conn)

			sec := CollectNftables(conn)
			if sec.Status != hostdoc.StatusCollected {
				t.Fatalf("a set that could not be read failed the whole section: status %q", sec.Status)
			}
			r := sec.Tables[0].Chains[0].Rules[0]
			if r.Text != bracket || r.Rendered != "partial" {
				t.Fatalf("got %q (%s), want %q (partial)", r.Text, r.Rendered, bracket)
			}
		})
	}
}

// A named set is something an operator maintains, and the agent reads none.
// The set's own record is fetched, because that is how the agent learns it
// is not anonymous. Its elements are never asked for.
func TestANamedSetOfStatesIsNotRead(t *testing.T) {
	named := &nftables.Set{Name: "allowed-states"}
	r, conn := collectWithSets(t, portThenStateLookup("allowed-states", false),
		map[string]*nftables.Set{"allowed-states": named},
		map[string][]nftables.SetElement{"allowed-states": keys(stateNew)})
	want := "meta l4proto tcp tcp dport 6000 [lookup @allowed-states] accept"
	if r.Text != want || r.Rendered != "partial" {
		t.Fatalf("got %q (%s), want %q (partial)", r.Text, r.Rendered, want)
	}
	if len(conn.askedElems) != 0 {
		t.Errorf("the elements of a named set were read: %v", conn.askedElems)
	}
}

// The reason the read is tied to the conntrack state: a set of addresses is
// the operator's list of who may connect or who is banned, and the agent
// must not fetch it, not even its record. This is fail2ban's rule on the
// production box, `ip saddr` looked up in a named set, and the same rule
// with an inline anonymous set.
func TestAnAddressSetIsNeverAskedFor(t *testing.T) {
	for _, setName := range []string{"addr-set-sshd", "__set1"} {
		t.Run(setName, func(t *testing.T) {
			rule := &nftables.Rule{Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(nftables.TableFamilyIPv4)}},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1,
					Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Lookup{SourceRegister: 1, SetName: setName},
				&expr.Verdict{Kind: expr.VerdictAccept},
			}}
			// The set exists, is anonymous and holds four-byte elements that
			// happen to be valid states, so only the register's kind keeps
			// the agent from reading it.
			r, conn := collectWithSets(t, rule,
				map[string]*nftables.Set{setName: anonymousSet(setName)},
				map[string][]nftables.SetElement{setName: keys(stateNew, stateUntracked)})
			want := "meta nfproto ipv4 [lookup @" + setName + "] accept"
			if r.Text != want || r.Rendered != "partial" {
				t.Fatalf("got %q (%s), want %q (partial)", r.Text, r.Rendered, want)
			}
			if len(conn.askedSets) != 0 || len(conn.askedElems) != 0 {
				t.Errorf("the agent asked for an address set: records %v, elements %v",
					conn.askedSets, conn.askedElems)
			}
		})
	}
}

// Three shapes that load a conntrack state and are still not the idiom.
// None of them may be rendered as a list of states, and none may read a set.
func TestOtherLookupsOnAConntrackStateStayABracket(t *testing.T) {
	sets := map[string]*nftables.Set{"__set0": anonymousSet("__set0")}
	elements := map[string][]nftables.SetElement{"__set0": keys(stateNew, stateUntracked)}

	t.Run("a map lookup that writes a register", func(t *testing.T) {
		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Lookup{SourceRegister: 1, DestRegister: 0, IsDestRegSet: true, SetName: "__set0"},
		}}
		r, conn := collectWithSets(t, rule, sets, elements)
		if r.Text != "[lookup @__set0]" {
			t.Fatalf("got %q, want the bracket: a verdict map is not a match", r.Text)
		}
		if len(conn.askedSets) != 0 {
			t.Errorf("a map was asked for: %v", conn.askedSets)
		}
	})

	t.Run("a state that was masked first", func(t *testing.T) {
		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: []byte{0x08, 0x00, 0x00, 0x00}, Xor: []byte{0x00, 0x00, 0x00, 0x00}},
			&expr.Lookup{SourceRegister: 1, SetName: "__set0"},
			&expr.Verdict{Kind: expr.VerdictAccept},
		}}
		r, conn := collectWithSets(t, rule, sets, elements)
		if r.Text != "[lookup @__set0] accept" || r.Rendered != "partial" {
			t.Fatalf("got %q (%s), want the bracket", r.Text, r.Rendered)
		}
		if len(conn.askedSets) != 0 {
			t.Errorf("a set was asked for behind a mask: %v", conn.askedSets)
		}
	})

	t.Run("another conntrack key", func(t *testing.T) {
		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATUS, Register: 1},
			&expr.Lookup{SourceRegister: 1, SetName: "__set0"},
			&expr.Verdict{Kind: expr.VerdictAccept},
		}}
		r, conn := collectWithSets(t, rule, sets, elements)
		if r.Text != "[lookup @__set0] accept" || r.Rendered != "partial" {
			t.Fatalf("got %q (%s), want the bracket", r.Text, r.Rendered)
		}
		if len(conn.askedSets) != 0 {
			t.Errorf("a set was asked for on ct status: %v", conn.askedSets)
		}
	})
}

// The comma form never was a lookup and must come out as it always did,
// with no set asked for.
func TestTheCommaFormOfCtStateIsUnchanged(t *testing.T) {
	rule := &nftables.Rule{Exprs: []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: []byte{0x48, 0x00, 0x00, 0x00}, Xor: []byte{0x00, 0x00, 0x00, 0x00}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x00}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}}
	r, conn := collectWithSets(t, rule, nil, nil)
	if r.Text != "ct state new,untracked accept" || r.Rendered != "full" {
		t.Fatalf("got %q (%s), want the comma form, full", r.Text, r.Rendered)
	}
	if len(conn.askedSets) != 0 {
		t.Errorf("a set was asked for by a rule that looks nothing up: %v", conn.askedSets)
	}
}

// renderRule with nothing to ask renders a state lookup as it always has,
// which is what every caller that holds no connection gets.
func TestRenderRuleWithoutAConnectionKeepsTheBracket(t *testing.T) {
	text, rendered := renderRule(nftables.TableFamilyINet, portThenStateLookup("__set0", false).Exprs)
	want := "meta l4proto tcp tcp dport 6000 [lookup @__set0] accept"
	if text != want || rendered != "partial" {
		t.Fatalf("got %q (%s), want %q (partial)", text, rendered, want)
	}
}
