//go:build linux

// This file is the nftables collector: the kernel's ruleset, read over the
// nf_tables netlink interface via github.com/google/nftables, the one
// permitted dependency (docs/PRODUCT.md 4e). Never by executing nft. The
// library only compiles on Linux, so everything touching it carries the linux
// build tag, and other platforms get an honest not_collected stub in cmd.
package collect

import (
	"encoding/binary"
	"errors"
	"os"
	"sort"

	"github.com/google/nftables"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// nftablesConn is the slice of *nftables.Conn this collector uses. It is an
// interface so the tests can feed constructed tables, chains and rules
// without a live kernel, the same fixture posture as the sockets collector.
type nftablesConn interface {
	ListTables() ([]*nftables.Table, error)
	ListChains() ([]*nftables.Chain, error)
	GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error)
	// The two set reads are used for one thing only, the conntrack states an
	// anonymous set holds (ctStateSet below). Both are netlink GETs.
	GetSetByName(t *nftables.Table, name string) (*nftables.Set, error)
	GetSetElements(s *nftables.Set) ([]nftables.SetElement, error)
}

// CollectNftablesLive opens the real netlink connection and collects. This is
// the only function that talks to the live kernel; everything below it is a
// pure function of what netlink returned.
func CollectNftablesLive() *hostdoc.NftablesSection {
	conn, err := nftables.New()
	if err != nil {
		return nftablesFailure(err)
	}
	return CollectNftables(conn)
}

// nftablesFailure maps a netlink error to a typed section status. The error
// text itself never enters the document (SI-8).
func nftablesFailure(err error) *hostdoc.NftablesSection {
	sec := &hostdoc.NftablesSection{}
	if errors.Is(err, os.ErrPermission) {
		sec.Status = hostdoc.StatusPermissionDenied
		sec.Cause = hostdoc.CausePermission
		return sec
	}
	sec.Status = hostdoc.StatusReadError
	sec.Cause = hostdoc.CauseNetlink
	return sec
}

// CollectNftables reads tables, chains and rules through conn and builds the
// section. Any netlink failure fails the whole section rather than shipping a
// silently truncated ruleset: a missing chain in a firewall listing is worse
// than an honest read_error.
func CollectNftables(conn nftablesConn) *hostdoc.NftablesSection {
	tables, err := conn.ListTables()
	if err != nil {
		return nftablesFailure(err)
	}
	chains, err := conn.ListChains()
	if err != nil {
		return nftablesFailure(err)
	}

	// Group chains under their owning table by family+name identity. Tables
	// and chains are sorted for deterministic output. Rules are NOT sorted:
	// their order inside a chain is the firewall's own evaluation order.
	type tableKey struct {
		family nftables.TableFamily
		name   string
	}
	byTable := map[tableKey][]*nftables.Chain{}
	for _, ch := range chains {
		if ch.Table == nil {
			// A chain netlink attributes to no table cannot be placed. Skip
			// it rather than invent an owner; the kernel does not produce
			// this shape.
			continue
		}
		k := tableKey{ch.Table.Family, ch.Table.Name}
		byTable[k] = append(byTable[k], ch)
	}

	sec := &hostdoc.NftablesSection{}
	sorted := make([]*nftables.Table, len(tables))
	copy(sorted, tables)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Family != sorted[j].Family {
			return familyName(sorted[i].Family) < familyName(sorted[j].Family)
		}
		return sorted[i].Name < sorted[j].Name
	})

	for _, tb := range sorted {
		out := hostdoc.NftTable{
			Family: familyName(tb.Family),
			Name:   sanitizeName(tb.Name),
		}
		tchains := byTable[tableKey{tb.Family, tb.Name}]
		sort.Slice(tchains, func(i, j int) bool { return tchains[i].Name < tchains[j].Name })
		for _, ch := range tchains {
			oc := hostdoc.NftChain{
				Name: sanitizeName(ch.Name),
				Type: sanitizeName(string(ch.Type)),
			}
			if ch.Hooknum != nil {
				oc.Hook = hookName(tb.Family, *ch.Hooknum)
			}
			if ch.Priority != nil {
				p := int32(*ch.Priority)
				oc.Priority = &p
			}
			if ch.Policy != nil {
				oc.Policy = policyName(*ch.Policy)
			}
			rules, err := conn.GetRules(tb, ch)
			if err != nil {
				return nftablesFailure(err)
			}
			// The renderer asks for a set only when a rule looks a conntrack
			// state up in one, so a set of addresses is never read.
			states := func(setName string) ([]uint32, bool) {
				return ctStateSet(conn, tb, setName)
			}
			for _, r := range rules {
				text, rendered := renderRuleWithSets(tb.Family, r.Exprs, states)
				oc.Rules = append(oc.Rules, hostdoc.NftRule{
					Text:     text,
					Rendered: rendered,
					Comment:  sanitizeName(ruleComment(r.UserData)),
				})
			}
			out.Chains = append(out.Chains, oc)
		}
		sec.Tables = append(sec.Tables, out)
	}

	sec.Status = hostdoc.StatusCollected
	return sec
}

// ctStateSet returns the conntrack states held by the anonymous set `name` in
// table tb, or false when it cannot say.
//
// It exists for one rule shape. firewalld 0.9.11, the RHEL 8 family's, opens
// a port as `tcp dport 6000 ct state { new, untracked } accept`
// (docs/RECORD.md 4.220). The braces make it a set lookup: nft sends
// `[ ct load state => reg 1 ] [ lookup reg 1 set __set0 ]` and an anonymous
// set whose two elements are 0x00000008 and 0x00000040 (read with
// `nft --debug=netlink`, nftables 1.1.3, 2026-10-02). Rendered as a bare
// `[lookup @__set0]` the words "ct state" are gone, and the reader cannot
// tell a rule open to every address from one open to a list of addresses.
//
// Everything about it is narrow on purpose. The caller asks only for a set a
// conntrack state is looked up in, so an address set is never read. The set
// has to be anonymous, which is the inline `{ ... }` form: a named set is
// something an operator maintains, and reading one is a decision this does
// not take. A map, an interval set, an element that is not exactly four
// bytes, an empty set and any netlink error all answer false, and the rule
// then keeps the bracket it always had. A failed set read does not fail the
// section, because nothing is left out: the rule is still there, graded
// partial.
func ctStateSet(conn nftablesConn, tb *nftables.Table, name string) ([]uint32, bool) {
	set, err := conn.GetSetByName(tb, name)
	if err != nil || set == nil {
		return nil, false
	}
	if !set.Anonymous || set.IsMap || set.Interval || set.Concatenation {
		return nil, false
	}
	elements, err := conn.GetSetElements(set)
	if err != nil || len(elements) == 0 {
		return nil, false
	}
	states := make([]uint32, 0, len(elements))
	for _, el := range elements {
		if el.IntervalEnd || len(el.Key) != 4 {
			return nil, false
		}
		// The state is a 32-bit value in the machine's own byte order, the
		// same register bytes ctStateNames reads a mask from, and the agent
		// is built for little-endian machines only.
		states = append(states, binary.LittleEndian.Uint32(el.Key))
	}
	return states, true
}

// familyName maps the netlink table family to the section's closed set of
// names. The values come from the library's own constants, never restated
// numbers, and anything else is "unknown" rather than a guess.
func familyName(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyNetdev:
		return "netdev"
	}
	return "unknown"
}

// hookName maps a chain hook to its name. Hook numbers are reused between
// families: the netdev family's ingress hook shares a number with
// prerouting, so the family decides the name, again via library constants.
func hookName(f nftables.TableFamily, h nftables.ChainHook) string {
	if f == nftables.TableFamilyNetdev {
		if h == *nftables.ChainHookIngress {
			return "ingress"
		}
		return "unknown"
	}
	switch h {
	case *nftables.ChainHookPrerouting:
		return "prerouting"
	case *nftables.ChainHookInput:
		return "input"
	case *nftables.ChainHookForward:
		return "forward"
	case *nftables.ChainHookOutput:
		return "output"
	case *nftables.ChainHookPostrouting:
		return "postrouting"
	}
	return "unknown"
}

// policyName maps a base chain policy. The kernel only defines accept and
// drop for chain policies; anything else is reported as empty rather than
// invented.
func policyName(p nftables.ChainPolicy) string {
	switch p {
	case nftables.ChainPolicyAccept:
		return "accept"
	case nftables.ChainPolicyDrop:
		return "drop"
	}
	return ""
}
