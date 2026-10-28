//go:build linux

// This file renders a rule's netlink expressions back into nft-like text.
// The kernel does not store rule text, only expression bytecode, so quoting a
// rule means rebuilding the text, and that rebuild must never overstate what
// it understood. Anything not understood becomes a bracketed placeholder and
// marks the rule "partial" or "none" (the accuracy rule). The rendered
// syntax is explicit rather than nft's shortest form: what
// matters is that a sysadmin reads the same meaning nft would print, not
// byte-identical output.
package collect

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// Conntrack state bits, from include/uapi/linux/netfilter/nf_conntrack_common.h:
// NF_CT_STATE_INVALID_BIT is 1<<0, NF_CT_STATE_BIT(ctinfo) is
// 1<<((ctinfo % IP_CT_IS_REPLY)+1) over the enum ESTABLISHED=0, RELATED=1,
// NEW=2, IS_REPLY=3, and NF_CT_STATE_UNTRACKED_BIT is 1<<6 (checked at the
// v6.12 tag, 2026-08-12).
var ctStateBits = []struct {
	bit  uint32
	name string
}{
	{1 << 0, "invalid"},
	{1 << 1, "established"},
	{1 << 2, "related"},
	{1 << 3, "new"},
	{1 << 6, "untracked"},
}

// regCtx describes what a register currently holds, so a following Cmp knows
// what it is comparing. kind is one of: proto, nfproto, port-sport, port-dport,
// addr4-s, addr4-d, addr6-s, addr6-d, iface, ctstate, rawpayload, hex.
type regCtx struct {
	kind   string
	prefix string // the text the comparison starts with, e.g. "tcp dport"
	mask   []byte // set by a preceding bitwise with zero xor
	// addr is set only when the register holds the leading bytes of an
	// address field but not all of them, which is how nftables stores an
	// address prefix. kind stays "raw" and prefix stays the exact
	// @base,offset,length text, so every path that cannot safely name the
	// prefix still renders exactly what it rendered before.
	addr *addrPrefixCtx
}

// addrPrefixCtx carries what naming an address prefix needs: which field the
// load started in, how wide that field is, and how many of its bytes the load
// actually read.
type addrPrefixCtx struct {
	name  string // "ip saddr", "ip6 daddr"
	width int    // the whole field in bytes, 4 or 16
	got   int    // bytes this load read, always fewer than width
}

// netAddrFields are the address fields of the two network headers, listed per
// the IP version that sees them. The offsets and widths are fixed by the
// protocol specifications: IPv4 carries the source address at byte 12 and the
// destination at byte 16, four bytes each (RFC 791 section 3.1), and IPv6
// carries them at bytes 8 and 24, sixteen bytes each (RFC 8200 section 3).
var netAddrFields = []struct {
	l3     string
	offset uint32
	width  uint32
	kind   string
	name   string
}{
	{"ip", 12, 4, "addr4", "ip saddr"},
	{"ip", 16, 4, "addr4", "ip daddr"},
	{"ip6", 8, 16, "addr6", "ip6 saddr"},
	{"ip6", 24, 16, "addr6", "ip6 daddr"},
}

// renderRule turns one rule's expressions into text plus the honesty grade:
// "full" when every expression was understood, "partial" when at least one
// fell back to a bracketed placeholder, "none" when nothing was understood.
func renderRule(family nftables.TableFamily, exprs []expr.Any) (string, string) {
	return renderRuleWithSets(family, exprs, nil)
}

// renderRuleWithSets is renderRule with one question it may ask outside the
// rule: which conntrack states the set of that name holds. ctStates is nil
// when there is nothing to ask, and then a lookup renders as it always has.
// It is asked only for a set that a conntrack state is looked up in.
func renderRuleWithSets(family nftables.TableFamily, exprs []expr.Any,
	ctStates func(setName string) ([]uint32, bool)) (string, string) {
	var tokens []string
	understood, fallback := 0, 0
	regs := map[uint32]regCtx{}
	// protoCtx remembers a matched l4proto ("tcp") so a later transport-header
	// load renders "tcp dport" instead of the anonymous "th dport".
	protoCtx := ""
	// l3Ctx disambiguates network-header offsets in the inet family, where a
	// rule may match either IP version. Set by the table family or by a
	// matched meta nfproto.
	l3Ctx := ""
	switch family {
	case nftables.TableFamilyIPv4:
		l3Ctx = "ip"
	case nftables.TableFamilyIPv6:
		l3Ctx = "ip6"
	}

	fall := func(format string, args ...any) {
		tokens = append(tokens, "["+fmt.Sprintf(format, args...)+"]")
		fallback++
	}
	emit := func(format string, args ...any) {
		tokens = append(tokens, fmt.Sprintf(format, args...))
		understood++
	}

	for _, e := range exprs {
		switch ex := e.(type) {

		case *expr.Meta:
			if ex.SourceRegister {
				// Writing a meta value is mangling, not matching. Out of the
				// v1 renderer's scope.
				fall("meta set")
				continue
			}
			switch ex.Key {
			case expr.MetaKeyL4PROTO:
				regs[ex.Register] = regCtx{kind: "proto", prefix: "meta l4proto"}
			case expr.MetaKeyNFPROTO:
				regs[ex.Register] = regCtx{kind: "nfproto", prefix: "meta nfproto"}
			case expr.MetaKeyIIFNAME:
				regs[ex.Register] = regCtx{kind: "iface", prefix: "iifname"}
			case expr.MetaKeyOIFNAME:
				regs[ex.Register] = regCtx{kind: "iface", prefix: "oifname"}
			case expr.MetaKeyMARK:
				regs[ex.Register] = regCtx{kind: "hex", prefix: "meta mark"}
			default:
				regs[ex.Register] = regCtx{kind: "hex", prefix: fmt.Sprintf("meta %d", ex.Key)}
			}

		case *expr.Payload:
			if ex.OperationType != expr.PayloadLoad {
				fall("payload write")
				continue
			}
			regs[ex.DestRegister] = payloadCtx(ex, l3Ctx, protoCtx)

		case *expr.Ct:
			if ex.SourceRegister {
				fall("ct set")
				continue
			}
			switch ex.Key {
			case expr.CtKeySTATE:
				regs[ex.Register] = regCtx{kind: "ctstate", prefix: "ct state"}
			case expr.CtKeySTATUS:
				regs[ex.Register] = regCtx{kind: "hex", prefix: "ct status"}
			case expr.CtKeyMARK:
				regs[ex.Register] = regCtx{kind: "hex", prefix: "ct mark"}
			case expr.CtKeyDIRECTION:
				regs[ex.Register] = regCtx{kind: "hex", prefix: "ct direction"}
			default:
				regs[ex.Register] = regCtx{kind: "hex", prefix: fmt.Sprintf("ct %d", ex.Key)}
			}

		case *expr.Bitwise:
			// The common masking idiom: same-register AND with a zero XOR.
			// Anything else changes the value in ways this renderer does not
			// model, so the register context is dropped to raw hex.
			src, ok := regs[ex.SourceRegister]
			if ok && allZero(ex.Xor) {
				src.mask = ex.Mask
				regs[ex.DestRegister] = src
			} else {
				regs[ex.DestRegister] = regCtx{kind: "hex", prefix: "bitwise"}
			}

		case *expr.Cmp:
			ctx, ok := regs[ex.Register]
			if !ok {
				fall("cmp on unknown register")
				continue
			}
			tok, ok := renderCmp(ctx, ex)
			if !ok {
				fall("cmp %s", ctx.prefix)
				continue
			}
			tokens = append(tokens, tok)
			understood++
			// A matched l4proto or nfproto becomes context for later loads.
			if ctx.kind == "proto" && ex.Op == expr.CmpOpEq && len(ex.Data) == 1 {
				if name, known := ipProtoNames[ex.Data[0]]; known {
					protoCtx = name
				}
			}
			if ctx.kind == "nfproto" && ex.Op == expr.CmpOpEq && len(ex.Data) == 1 {
				switch nftables.TableFamily(ex.Data[0]) {
				case nftables.TableFamilyIPv4:
					l3Ctx = "ip"
				case nftables.TableFamilyIPv6:
					l3Ctx = "ip6"
				}
			}

		case *expr.Counter:
			// The live packet and byte counts are runtime state, not rule
			// text, and would make two identical collections differ. The
			// keyword alone is the rule.
			emit("counter")

		case *expr.Verdict:
			switch ex.Kind {
			case expr.VerdictAccept:
				emit("accept")
			case expr.VerdictDrop:
				emit("drop")
			case expr.VerdictReturn:
				emit("return")
			case expr.VerdictJump:
				emit("jump %s", sanitizeName(ex.Chain))
			case expr.VerdictGoto:
				emit("goto %s", sanitizeName(ex.Chain))
			case expr.VerdictQueue:
				emit("queue")
			case expr.VerdictContinue:
				emit("continue")
			default:
				fall("verdict %d", ex.Kind)
			}

		case *expr.Match:
			fall("xt match %s", sanitizeName(ex.Name))
		case *expr.Target:
			fall("xt target %s", sanitizeName(ex.Name))
		case *expr.Lookup:
			// A map lookup can write its result register; whatever context
			// that register held no longer describes it.
			if ex.IsDestRegSet {
				delete(regs, ex.DestRegister)
			}
			if text, ok := ctStateLookup(regs, ex, ctStates); ok {
				emit("%s", text)
				continue
			}
			fall("lookup @%s", sanitizeName(ex.SetName))
		case *expr.Limit:
			// `limit rate over N` matches only what is above the rate, the
			// opposite of a plain limit: an accept behind it lets through
			// the excess and nothing else. The two are told apart so that
			// nothing reading the rule takes one for the other. The rate
			// itself is not rendered either way.
			if ex.Over {
				fall("limit over")
			} else {
				fall("limit")
			}
		case *expr.Log:
			fall("log")
		case *expr.Masq:
			fall("masquerade")
		case *expr.NAT:
			fall("nat")
		case *expr.Redir:
			fall("redirect")
		case *expr.Reject:
			fall("reject")
		case *expr.Immediate:
			// An immediate into a data register feeds a later expression
			// (nat addresses, set elements). Meaningless alone, so it is
			// silent, but the register no longer holds what a load put there.
			delete(regs, ex.Register)

		default:
			// An expression this renderer does not model may write any
			// register (fib is the live example: it loads a route lookup
			// result into a register a stale meta context still claimed).
			// Drop every context so a following Cmp falls back honestly
			// instead of rendering wrong text as understood.
			regs = map[uint32]regCtx{}
			fall("expr %s", exprTypeName(e))
		}
	}

	text := strings.Join(tokens, " ")
	switch {
	case fallback == 0 && understood > 0:
		return text, "full"
	case understood == 0:
		return text, "none"
	default:
		return text, "partial"
	}
}

// payloadCtx classifies a payload load by header base, offset and length.
// The named offsets are fixed by the protocol specifications: IPv4 puts
// protocol at byte 9 and the addresses at 12 and 16 (RFC 791 section 3.1),
// IPv6 puts next-header at byte 6 and the addresses at 8 and 24 (RFC 8200
// section 3), and TCP, UDP and SCTP all start with source then destination
// port as two bytes each. Anything else renders in nft's raw
// @base,offset,length form, in bits, which is exact rather than guessed.
//
// A load that starts at an address field and reads fewer bytes than the field
// holds is how nftables stores a prefix match, so it is marked as one. It is
// still given the raw prefix text, because whether it can honestly be named
// also depends on the comparison that follows it, and that is renderCmp's
// call.
func payloadCtx(p *expr.Payload, l3, proto string) regCtx {
	th := "th"
	if proto != "" {
		th = proto
	}
	switch p.Base {
	case expr.PayloadBaseTransportHeader:
		switch {
		case p.Offset == 0 && p.Len == 2:
			return regCtx{kind: "port", prefix: th + " sport"}
		case p.Offset == 2 && p.Len == 2:
			return regCtx{kind: "port", prefix: th + " dport"}
		}
		return regCtx{kind: "raw", prefix: fmt.Sprintf("@th,%d,%d", p.Offset*8, p.Len*8)}
	case expr.PayloadBaseNetworkHeader:
		if l3 == "ip" && p.Offset == 9 && p.Len == 1 {
			return regCtx{kind: "proto", prefix: "ip protocol"}
		}
		if l3 == "ip6" && p.Offset == 6 && p.Len == 1 {
			return regCtx{kind: "proto", prefix: "ip6 nexthdr"}
		}
		raw := regCtx{kind: "raw", prefix: fmt.Sprintf("@nh,%d,%d", p.Offset*8, p.Len*8)}
		for _, f := range netAddrFields {
			// The family has to be pinned and the load has to begin exactly
			// where the field begins. An inet table sees both headers, so an
			// offset alone says nothing about which one is being read.
			if f.l3 != l3 || p.Offset != f.offset {
				continue
			}
			switch {
			case p.Len == f.width:
				// The whole field: the address itself.
				return regCtx{kind: f.kind, prefix: f.name}
			case p.Len > 0 && p.Len < f.width:
				// Fewer bytes, from the front of the field: a prefix. A load
				// of f.width or more bytes is deliberately not one, because
				// it ends outside the field and so is not this field at all.
				raw.addr = &addrPrefixCtx{name: f.name, width: int(f.width), got: int(p.Len)}
			}
			break
		}
		return raw
	default:
		return regCtx{kind: "raw", prefix: fmt.Sprintf("@ll,%d,%d", p.Offset*8, p.Len*8)}
	}
}

// addrText writes a whole address field as an address.
//
// net/netip rather than net.IP because net.IP.String prints a sixteen-byte
// IPv4-mapped address as a plain dotted quad, which would show an IPv6 rule as
// if it matched an IPv4 address. netip keeps the family it was given.
func addrText(b []byte) string {
	switch len(b) {
	case 4:
		return netip.AddrFrom4([4]byte(b)).String()
	case 16:
		return netip.AddrFrom16([16]byte(b)).String()
	}
	// Unreachable from the callers, which both check the width first. Kept as
	// hex rather than as a panic, because this renderer reads whatever the
	// kernel handed it.
	return fmt.Sprintf("0x%x", b)
}

// addrPrefixText writes the leading bytes of an address field as an address
// and a prefix length.
//
// A payload load reads a header field from its first byte onwards, and both IP
// versions store an address most significant byte first, so n leading bytes
// fix exactly the top 8n bits and nothing below them. That is what a /8n
// prefix means, which is why the trailing bytes are zero here: they were never
// read and the rule does not constrain them.
func addrPrefixText(width int, data []byte) string {
	full := make([]byte, width)
	copy(full, data)
	return fmt.Sprintf("%s/%d", addrText(full), len(data)*8)
}

// renderCmp renders one comparison against what the register holds. The
// second return is false when this combination is not understood, and the
// caller falls back rather than print something half right.
func renderCmp(ctx regCtx, c *expr.Cmp) (string, bool) {
	op, ok := cmpOp(c.Op)
	if !ok {
		return "", false
	}
	// The conntrack idiom: state AND mask, compared unequal to zero, is nft's
	// "ct state a,b". Any other masked comparison renders explicitly.
	if ctx.kind == "ctstate" {
		if ctx.mask != nil && c.Op == expr.CmpOpNeq && allZero(c.Data) {
			return "ct state " + ctStateNames(ctx.mask), true
		}
		return "", false
	}
	if ctx.mask != nil {
		return fmt.Sprintf("%s & 0x%x %s 0x%x", ctx.prefix, ctx.mask, opOrEqExplicit(op), c.Data), true
	}
	// An address field the load only partly covered is a prefix match, and it
	// can be named only under equality and only when the comparison describes
	// exactly the bytes the load read. Under any other operator, or against a
	// different width, the prefix notation would state something about bits
	// nobody looked at, so the exact raw form below is used instead.
	if ctx.addr != nil && c.Op == expr.CmpOpEq && len(c.Data) == ctx.addr.got {
		return ctx.addr.name + " " + addrPrefixText(ctx.addr.width, c.Data), true
	}

	val := ""
	switch ctx.kind {
	case "port":
		if len(c.Data) != 2 {
			return "", false
		}
		val = fmt.Sprintf("%d", uint16(c.Data[0])<<8|uint16(c.Data[1]))
	case "addr4":
		if len(c.Data) != 4 {
			return "", false
		}
		val = addrText(c.Data)
	case "addr6":
		if len(c.Data) != 16 {
			return "", false
		}
		val = addrText(c.Data)
	case "proto":
		if len(c.Data) != 1 {
			return "", false
		}
		if name, known := ipProtoNames[c.Data[0]]; known {
			val = name
		} else {
			val = fmt.Sprintf("%d", c.Data[0])
		}
	case "nfproto":
		if len(c.Data) != 1 {
			return "", false
		}
		switch nftables.TableFamily(c.Data[0]) {
		case nftables.TableFamilyIPv4:
			val = "ipv4"
		case nftables.TableFamilyIPv6:
			val = "ipv6"
		default:
			val = fmt.Sprintf("%d", c.Data[0])
		}
	case "iface":
		val = fmt.Sprintf("%q", sanitizeName(strings.TrimRight(string(c.Data), "\x00")))
	case "hex", "raw":
		val = fmt.Sprintf("0x%x", c.Data)
	default:
		return "", false
	}
	if op == "" {
		return ctx.prefix + " " + val, true
	}
	return ctx.prefix + " " + op + " " + val, true
}

// cmpOp maps a comparison operator to nft's notation. Equality renders as
// nothing, matching nft's own shorthand.
func cmpOp(op expr.CmpOp) (string, bool) {
	switch op {
	case expr.CmpOpEq:
		return "", true
	case expr.CmpOpNeq:
		return "!=", true
	case expr.CmpOpLt:
		return "<", true
	case expr.CmpOpLte:
		return "<=", true
	case expr.CmpOpGt:
		return ">", true
	case expr.CmpOpGte:
		return ">=", true
	}
	return "", false
}

// opOrEqExplicit writes equality out as == where leaving it implicit would be
// ambiguous, inside masked comparisons.
func opOrEqExplicit(op string) string {
	if op == "" {
		return "=="
	}
	return op
}

// ctStateLookup renders a lookup of a conntrack state in a set of states as
// nft's own `ct state { new, untracked }`, and answers false for every
// lookup that is not exactly that.
//
// The register has to hold the unmasked conntrack state, the lookup has to
// be a match and not a map, and every element has to be exactly one state
// this file can name. One element that is two bits at once, or a bit nobody
// defined, and the whole lookup stays a bracket: a list with a name missing
// would read as a shorter list, which is a different rule.
func ctStateLookup(regs map[uint32]regCtx, lookup *expr.Lookup,
	ctStates func(setName string) ([]uint32, bool)) (string, bool) {
	if ctStates == nil || lookup.IsDestRegSet {
		return "", false
	}
	ctx, ok := regs[lookup.SourceRegister]
	if !ok || ctx.kind != "ctstate" || ctx.mask != nil {
		return "", false
	}
	states, ok := ctStates(lookup.SetName)
	if !ok || len(states) == 0 {
		return "", false
	}
	held := map[uint32]bool{}
	for _, state := range states {
		named := false
		for _, b := range ctStateBits {
			if state == b.bit {
				named = true
			}
		}
		if !named {
			return "", false
		}
		held[state] = true
	}
	// In the order of the bits, so two collections of one ruleset read the
	// same whatever order the kernel handed the elements back in.
	var names []string
	for _, b := range ctStateBits {
		if held[b.bit] {
			names = append(names, b.name)
		}
	}
	op := ""
	if lookup.Invert {
		op = "!= "
	}
	return "ct state " + op + "{ " + strings.Join(names, ", ") + " }", true
}

// ctStateNames renders a conntrack state mask as nft's comma list. Bits the
// mask carries beyond the defined ones are kept as hex rather than dropped.
func ctStateNames(mask []byte) string {
	// The mask arrives as the register's little-endian bytes.
	var m uint32
	for i := len(mask) - 1; i >= 0; i-- {
		m = m<<8 | uint32(mask[i])
	}
	var names []string
	for _, b := range ctStateBits {
		if m&b.bit != 0 {
			names = append(names, b.name)
			m &^= b.bit
		}
	}
	if m != 0 {
		names = append(names, fmt.Sprintf("0x%x", m))
	}
	if len(names) == 0 {
		return "0x0"
	}
	return strings.Join(names, ",")
}

// exprTypeName names an expression type for a placeholder, without the
// package path noise.
func exprTypeName(e expr.Any) string {
	return strings.TrimPrefix(fmt.Sprintf("%T", e), "*expr.")
}
