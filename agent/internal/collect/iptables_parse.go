// This file is the legacy x_tables PARSER, deliberately free of build tags
// and syscalls: a pure function of bytes the kernel (or a hostile test, or
// the fuzzer) hands over. The syscall half lives in iptables_linux.go. Every
// struct offset comes from the kernel uapi headers at the v6.8 tag, read
// 2026-08-13: linux/netfilter_ipv4/ip_tables.h,
// linux/netfilter_ipv6/ip6_tables.h and linux/netfilter/x_tables.h.
package collect

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// Constants from the uapi headers named above.
const (
	xtTableNameLen = 32 // XT_TABLE_MAXNAMELEN
	xtExtNameLen   = 29 // XT_EXTENSION_MAXNAMELEN
	xtFuncNameLen  = 30 // XT_FUNCTION_MAXNAMELEN
	xtMatchHdrLen  = 32 // u16 size, name[29], u8 revision

	// Inversion bits, identical in both families for the fields this
	// renderer handles. XT_INV_PROTO comes from x_tables.h.
	xtInvViaIn  = 0x01
	xtInvViaOut = 0x02
	xtInvSrcIP  = 0x08
	xtInvDstIP  = 0x10
	xtInvFrag   = 0x20 // v4 only
	xtInvProto  = 0x40

	errorTarget = "ERROR"
	numHooks    = 5
)

// hookChainNames maps the netfilter inet hooks to their chain names, in hook
// order (NF_INET_PRE_ROUTING through NF_INET_POST_ROUTING).
var hookChainNames = [numHooks]string{
	"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING",
}

// legacyTables is every table the x_tables modules register. Only the ones
// the kernel already lists are asked about, and every other one becomes a
// not_present source without a call (iptables_present.go).
var legacyTables = []string{"filter", "nat", "mangle", "raw", "security"}

// legacyFamily parameterises the two collectors. The wire layouts differ in
// the IP-criteria block at the front of each entry, so every offset into
// that block is spelled out per family rather than derived, because the v6
// struct carries three bytes of tail padding that broke the derived version.
//
// v4, struct ipt_ip (84 bytes): src 0, dst 4, smsk 8, dmsk 12, ifaces 16,
// iface masks 48, proto 80, flags 82, invflags 83.
// v6, struct ip6t_ip6 (136 bytes): src 0, dst 16, smsk 32, dmsk 48, ifaces
// 64, iface masks 96, proto 128, tos 130, flags 131, invflags 132, pad to
// 136.
type legacyFamily struct {
	// af and level are the socket family and getsockopt level, set by the
	// linux half; zero in the parse-only configs the portable tests use.
	af, level int
	ipLen     int // sizeof the IP-criteria struct
	entryHdr  int // offset of elems[] in the entry
	addrLen   int
	ifaceOff  int // in-interface name; out follows 16 later, masks 32 later
	protoOff  int
	flagsOff  int
	invOff    int
	fFragBit  byte // 0 when the family has no fragment flag
	fGotoBit  byte
	fProtoBit byte // 0 when protocol presence is not flag-gated

	// Where the kernel says which tables it holds, read before any table is
	// asked about (iptables_present.go). namesFile is the list of this
	// family's tables in the reader's network namespace, coreModule the
	// module that list belongs to, and tableModule the prefix each table's
	// own module carries: iptable_filter, ip6table_nat.
	namesFile   string
	coreModule  string
	tableModule string
}

var (
	v4Parse = legacyFamily{
		ipLen: 84, entryHdr: 112, addrLen: 4,
		ifaceOff: 16, protoOff: 80, flagsOff: 82, invOff: 83,
		fFragBit: 0x01, fGotoBit: 0x02, // IPT_F_FRAG, IPT_F_GOTO
		namesFile: "/proc/net/ip_tables_names", coreModule: "ip_tables", tableModule: "iptable_",
	}
	v6Parse = legacyFamily{
		ipLen: 136, entryHdr: 168, addrLen: 16,
		ifaceOff: 64, protoOff: 128, flagsOff: 131, invOff: 132,
		fGotoBit: 0x04, fProtoBit: 0x01, // IP6T_F_GOTO, IP6T_F_PROTO
		namesFile: "/proc/net/ip6_tables_names", coreModule: "ip6_tables", tableModule: "ip6table_",
	}
)

// legacyInfo is the parsed struct ipt_getinfo / ip6t_getinfo: name[32],
// valid_hooks at 32, hook_entry[5] at 36, underflow[5] at 56, num_entries at
// 76, size at 80.
type legacyInfo struct {
	validHooks uint32
	hookEntry  [numHooks]uint32
	underflow  [numHooks]uint32
	numEntries uint32
	size       uint32
}

// ipProtoNames covers the common IANA protocol numbers. An unlisted protocol
// renders as its decimal number, which is the verbatim truth, not a guess.
var ipProtoNames = map[byte]string{
	1:   "icmp",
	6:   "tcp",
	17:  "udp",
	47:  "gre",
	50:  "esp",
	51:  "ah",
	58:  "icmpv6",
	132: "sctp",
}

// allZero reports whether every byte is zero. True for an empty slice.
func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// legacyChain accumulates one chain during parsing.
type legacyChain struct {
	name    string
	builtin bool
	policy  string
	entries []legacyEntry
}

// parseLegacyTable rebuilds chains and rules from one table's entry blob,
// the same walk iptables-save performs: builtin chains start at the hook
// entries, an ERROR-target entry names the user chain that follows it, each
// builtin's underflow entry is its policy, and a final ERROR entry ends the
// blob. Two passes: the first assigns entries to chains, the second renders,
// because a jump can point at a user chain that appears later in the blob.
func parseLegacyTable(fam legacyFamily, tableName string, info legacyInfo, blob []byte) (hostdoc.IptTable, error) {
	table := hostdoc.IptTable{Name: sanitizeName(tableName)}
	if len(blob) != int(info.size) {
		return table, fmt.Errorf("blob size %d does not match declared size %d", len(blob), info.size)
	}

	var chains []*legacyChain
	startToChain := map[uint32]*legacyChain{}
	underflowOf := map[uint32]*legacyChain{}
	for i := 0; i < numHooks; i++ {
		if info.validHooks&(1<<uint(i)) == 0 {
			continue
		}
		c := &legacyChain{name: hookChainNames[i], builtin: true}
		chains = append(chains, c)
		startToChain[info.hookEntry[i]] = c
		underflowOf[info.underflow[i]] = c
	}

	// Pass one: walk every entry. The offset advances strictly, so a
	// hostile blob cannot loop the walk.
	var current *legacyChain
	pendingUser := ""
	sawPendingUser := false
	off := uint32(0)
	entryCount := 0
	for off < info.size {
		entryCount++
		if entryCount > int(info.numEntries) || entryCount > 1<<20 {
			return table, fmt.Errorf("more entries than the table declared")
		}
		e, err := readLegacyEntry(fam, blob, off)
		if err != nil {
			return table, err
		}

		if c, ok := startToChain[off]; ok {
			current = c
		} else if sawPendingUser {
			c := &legacyChain{name: pendingUser}
			chains = append(chains, c)
			startToChain[off] = c
			current = c
			sawPendingUser = false
		}

		switch {
		case e.isError:
			// Names the chain that starts at the next entry; the final
			// ERROR entry simply ends the table.
			pendingUser = e.errorName
			sawPendingUser = true
			current = nil
		case underflowOf[off] != nil && e.unconditional && e.isStandard &&
			legacyPolicyName(e.verdict) != "":
			underflowOf[off].policy = legacyPolicyName(e.verdict)
		default:
			if current == nil {
				return table, fmt.Errorf("entry at %d belongs to no chain", off)
			}
			current.entries = append(current.entries, e)
		}

		off += uint32(e.next)
	}
	if off != info.size {
		return table, fmt.Errorf("entries overran the declared size")
	}

	// A user chain's final unconditional RETURN is the implicit one every
	// chain carries on the wire. iptables-save omits it and so do we, with
	// the same ambiguity: an explicit trailing unconditional -j RETURN is
	// stored identically and cannot be told apart.
	for _, c := range chains {
		if !c.builtin && len(c.entries) > 0 {
			last := c.entries[len(c.entries)-1]
			if last.unconditional && last.isStandard && last.verdict == -5 && len(last.matches) == 0 {
				c.entries = c.entries[:len(c.entries)-1]
			}
		}
	}

	// Pass two: render, with the chain map complete so forward jumps
	// resolve by target offset.
	chainAt := func(target uint32) string {
		if c, ok := startToChain[target]; ok {
			return c.name
		}
		return ""
	}
	for _, c := range chains {
		oc := hostdoc.IptChain{
			Name:    sanitizeName(c.name),
			BuiltIn: c.builtin,
			Policy:  c.policy,
		}
		for _, e := range c.entries {
			oc.Rules = append(oc.Rules, renderLegacyRule(fam, e, chainAt))
		}
		table.Chains = append(table.Chains, oc)
	}
	// Builtins keep hook order at the front; user chains sort by name after
	// them. Rule order inside a chain is evaluation order, never touched.
	sort.SliceStable(table.Chains, func(i, j int) bool {
		a, b := table.Chains[i], table.Chains[j]
		if a.BuiltIn != b.BuiltIn {
			return a.BuiltIn
		}
		if a.BuiltIn {
			return false
		}
		return a.Name < b.Name
	})
	return table, nil
}

// legacyEntry is one decoded entry, enough of it to classify and render.
type legacyEntry struct {
	ipBytes       []byte
	flags         byte
	inv           byte
	matches       []string
	targetName    string
	isStandard    bool
	isError       bool
	errorName     string
	verdict       int32
	goodVerdict   bool
	unconditional bool
	next          int
}

// readLegacyEntry decodes the entry at off, bounds-checked at every step:
// the blob is kernel memory on a healthy host and arbitrary bytes in a
// hostile test, and the two must parse identically or fail loudly.
func readLegacyEntry(fam legacyFamily, blob []byte, off uint32) (legacyEntry, error) {
	var e legacyEntry
	if int(off)+fam.entryHdr > len(blob) {
		return e, fmt.Errorf("entry header at %d past end", off)
	}
	ent := blob[off:]
	le := binary.LittleEndian
	targetOff := le.Uint16(ent[fam.ipLen+4:])
	nextOff := le.Uint16(ent[fam.ipLen+6:])
	if int(nextOff) < fam.entryHdr || int(off)+int(nextOff) > len(blob) ||
		int(targetOff) < fam.entryHdr || int(targetOff) > int(nextOff) {
		return e, fmt.Errorf("entry at %d has inconsistent offsets", off)
	}
	e.next = int(nextOff)
	e.ipBytes = ent[:fam.ipLen]
	e.flags = ent[fam.flagsOff]
	e.inv = ent[fam.invOff]
	e.unconditional = allZero(e.ipBytes) && int(targetOff) == fam.entryHdr

	// Matches sit between the entry header and the target.
	m := uint32(fam.entryHdr)
	for m < uint32(targetOff) {
		if m+xtMatchHdrLen > uint32(targetOff) {
			return e, fmt.Errorf("match header at %d past target", off+m)
		}
		msize := le.Uint16(ent[m:])
		if int(msize) < xtMatchHdrLen || m+uint32(msize) > uint32(targetOff) {
			return e, fmt.Errorf("match at %d has bad size", off+m)
		}
		e.matches = append(e.matches, cString(ent[m+2:m+2+xtExtNameLen]))
		m += uint32(msize)
	}

	// The target.
	t := uint32(targetOff)
	tsize := le.Uint16(ent[t:])
	if int(tsize) < xtMatchHdrLen || t+uint32(tsize) > uint32(nextOff) {
		return e, fmt.Errorf("target at %d has bad size", off+t)
	}
	e.targetName = cString(ent[t+2 : t+2+xtExtNameLen])
	switch e.targetName {
	case "": // XT_STANDARD_TARGET is the empty name
		e.isStandard = true
		if int(tsize) >= xtMatchHdrLen+4 {
			e.verdict = int32(le.Uint32(ent[t+xtMatchHdrLen:]))
			e.goodVerdict = true
		}
	case errorTarget:
		e.isError = true
		if t+xtMatchHdrLen+xtFuncNameLen <= uint32(nextOff) {
			e.errorName = cString(ent[t+xtMatchHdrLen : t+xtMatchHdrLen+xtFuncNameLen])
		}
	}
	return e, nil
}

// legacyPolicyName maps an underflow verdict to a policy word. Standard
// verdicts encode as -(NF verdict)-1, with NF_DROP 0 and NF_ACCEPT 1.
func legacyPolicyName(v int32) string {
	switch v {
	case -1:
		return "drop"
	case -2:
		return "accept"
	}
	return ""
}

// renderLegacyRule builds the rule text in iptables' own option vocabulary,
// with the same honesty rule as the nftables renderer: extension matches and
// targets are named in brackets and grade the rule partial, because their
// binary payloads are not decoded in v1.
func renderLegacyRule(fam legacyFamily, e legacyEntry, chainAt func(uint32) string) hostdoc.IptRule {
	var parts []string
	understood, fallback := 0, 0
	le := binary.LittleEndian

	bang := func(bit byte) string {
		if e.inv&bit != 0 {
			return "! "
		}
		return ""
	}

	// Protocol. v4 treats a nonzero protocol as active; v6 gates it behind
	// IP6T_F_PROTO.
	proto := le.Uint16(e.ipBytes[fam.protoOff:])
	protoActive := proto != 0
	if fam.fProtoBit != 0 {
		protoActive = e.flags&fam.fProtoBit != 0
	}
	if protoActive {
		name := fmt.Sprintf("%d", proto)
		if proto <= 255 {
			if n, ok := ipProtoNames[byte(proto)]; ok {
				name = n
			}
		}
		parts = append(parts, bang(xtInvProto)+"-p "+name)
		understood++
	}

	// Source and destination with their masks. An all-zero mask means the
	// criterion is unset.
	addr := func(base int, flag string, bit byte) {
		a := e.ipBytes[base : base+fam.addrLen]
		m := e.ipBytes[base+2*fam.addrLen : base+3*fam.addrLen]
		if allZero(m) {
			return
		}
		parts = append(parts, fmt.Sprintf("%s%s %s/%s", bang(bit), flag, net.IP(a).String(), maskText(m)))
		understood++
	}
	addr(0, "-s", xtInvSrcIP)
	addr(fam.addrLen, "-d", xtInvDstIP)

	// Interfaces. The stored name is printed verbatim: a wildcard is stored
	// with its trailing plus already in the name (checked live against
	// iptables-legacy -S on kernel 6.8, 2026-08-13, after a first version
	// wrongly re-appended the plus). The mask only says whether the
	// criterion is set at all.
	iface := func(nameOff, maskOff int, flag string, bit byte) {
		mask := e.ipBytes[maskOff : maskOff+16]
		if allZero(mask) {
			return
		}
		name := cString(e.ipBytes[nameOff : nameOff+16])
		parts = append(parts, fmt.Sprintf("%s%s %s", bang(bit), flag, sanitizeName(name)))
		understood++
	}
	iface(fam.ifaceOff, fam.ifaceOff+32, "-i", xtInvViaIn)
	iface(fam.ifaceOff+16, fam.ifaceOff+48, "-o", xtInvViaOut)

	// The v4 fragment flag.
	if fam.fFragBit != 0 && e.flags&fam.fFragBit != 0 {
		parts = append(parts, bang(xtInvFrag)+"-f")
		understood++
	}

	for _, m := range e.matches {
		parts = append(parts, "[xt match "+sanitizeName(m)+"]")
		fallback++
	}

	switch {
	case e.isStandard && e.goodVerdict && e.verdict < 0:
		switch e.verdict {
		case -1:
			parts = append(parts, "drop")
			understood++
		case -2:
			parts = append(parts, "accept")
			understood++
		case -4:
			parts = append(parts, "queue")
			understood++
		case -5:
			parts = append(parts, "return")
			understood++
		default:
			parts = append(parts, fmt.Sprintf("[verdict %d]", e.verdict))
			fallback++
		}
	case e.isStandard && e.goodVerdict:
		jump := "jump"
		if e.flags&fam.fGotoBit != 0 {
			jump = "goto"
		}
		if name := chainAt(uint32(e.verdict)); name != "" {
			parts = append(parts, jump+" "+sanitizeName(name))
			understood++
		} else {
			parts = append(parts, fmt.Sprintf("[%s to offset %d]", jump, e.verdict))
			fallback++
		}
	case e.targetName != "":
		parts = append(parts, "[xt target "+sanitizeName(e.targetName)+"]")
		fallback++
	default:
		parts = append(parts, "[target unreadable]")
		fallback++
	}

	text := strings.Join(parts, " ")
	rendered := "partial"
	switch {
	case fallback == 0 && understood > 0:
		rendered = "full"
	case understood == 0:
		rendered = "none"
	}
	return hostdoc.IptRule{Text: text, Rendered: rendered}
}

// maskText renders a netmask as a prefix length when contiguous and as the
// raw mask otherwise, which is rare but expressible in iptables.
func maskText(m []byte) string {
	ones := 0
	seenZero := false
	for _, b := range m {
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) != 0 {
				if seenZero {
					return net.IP(m).String()
				}
				ones++
			} else {
				seenZero = true
			}
		}
	}
	return fmt.Sprintf("%d", ones)
}

// cString reads a NUL-terminated string from a fixed-width field.
func cString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
