package collect

// The legacy parser's review, portable on purpose: the parser is a pure
// function, so its tests and the fuzzer run on any platform. The builder below constructs entry blobs to
// the same uapi layout the parser reads, which makes these tests exact but
// self-referential; the independent check is the live run against a real
// kernel's tables, recorded in the PR. Hostile cases are the point here: the
// parser must fail loudly on any blob a kernel would not produce.

import (
	"encoding/binary"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// blobBuilder accumulates ipt_entry records for the v4 layout.
type blobBuilder struct {
	buf []byte
}

// entrySpec describes one v4 entry to append.
type entrySpec struct {
	src, smsk    [4]byte
	dst, dmsk    [4]byte
	iniface      string
	inifaceExact bool
	proto        uint16
	flags, inv   byte
	matches      []string
	targetName   string // "" for standard, "ERROR" for error
	verdict      int32  // standard target verdict or jump offset
	errorName    string
}

func (b *blobBuilder) add(e entrySpec) uint32 {
	off := uint32(len(b.buf))
	ip := make([]byte, 84)
	copy(ip[0:], e.src[:])
	copy(ip[4:], e.dst[:])
	copy(ip[8:], e.smsk[:])
	copy(ip[12:], e.dmsk[:])
	copy(ip[16:], e.iniface)
	if e.iniface != "" {
		n := len(e.iniface)
		for i := 0; i < n; i++ {
			ip[48+i] = 0xff
		}
		if e.inifaceExact {
			ip[48+n] = 0xff
		}
	}
	binary.LittleEndian.PutUint16(ip[80:], e.proto)
	ip[82] = e.flags
	ip[83] = e.inv

	var matches []byte
	for _, name := range e.matches {
		m := make([]byte, 48) // header 32 plus 16 bytes of undecoded payload
		binary.LittleEndian.PutUint16(m[0:], 48)
		copy(m[2:2+29], name)
		matches = append(matches, m...)
	}

	var target []byte
	switch e.targetName {
	case "":
		target = make([]byte, 40) // header 32 + verdict, padded to align 8
		binary.LittleEndian.PutUint16(target[0:], 40)
		binary.LittleEndian.PutUint32(target[32:], uint32(e.verdict))
	case "ERROR":
		target = make([]byte, 64) // header 32 + errorname 30, padded
		binary.LittleEndian.PutUint16(target[0:], 64)
		copy(target[2:2+29], "ERROR")
		copy(target[32:32+30], e.errorName)
	default:
		target = make([]byte, 40)
		binary.LittleEndian.PutUint16(target[0:], 40)
		copy(target[2:2+29], e.targetName)
	}

	entry := make([]byte, 112)
	copy(entry[0:84], ip)
	targetOff := 112 + len(matches)
	next := targetOff + len(target)
	binary.LittleEndian.PutUint16(entry[88:], uint16(targetOff))
	binary.LittleEndian.PutUint16(entry[90:], uint16(next))
	b.buf = append(b.buf, entry...)
	b.buf = append(b.buf, matches...)
	b.buf = append(b.buf, target...)
	return off
}

// buildFilterTable assembles a filter-style table: INPUT, FORWARD and OUTPUT
// builtins with policies, the given user chains, and the closing ERROR
// entry, returning info and blob the way the kernel hands them over.
func buildFilterTable(t *testing.T, build func(b *blobBuilder) (hooks [numHooks]uint32, under [numHooks]uint32, valid uint32)) (legacyInfo, []byte) {
	t.Helper()
	var b blobBuilder
	hooks, under, valid := build(&b)
	// The table always ends with an ERROR entry.
	b.add(entrySpec{targetName: "ERROR", errorName: "ERROR"})
	info := legacyInfo{
		validHooks: valid,
		hookEntry:  hooks,
		underflow:  under,
		size:       uint32(len(b.buf)),
	}
	// Count entries by walking next offsets.
	n := uint32(0)
	for off := 0; off < len(b.buf); {
		n++
		off += int(binary.LittleEndian.Uint16(b.buf[off+90:]))
	}
	info.numEntries = n
	return info, b.buf
}

func TestLegacyMinimalFilterTable(t *testing.T) {
	info, blob := buildFilterTable(t, func(b *blobBuilder) ([numHooks]uint32, [numHooks]uint32, uint32) {
		var hooks, under [numHooks]uint32
		// INPUT with one rule and policy DROP.
		hooks[1] = b.add(entrySpec{
			proto: 6, src: [4]byte{192, 0, 2, 0}, smsk: [4]byte{255, 255, 255, 0},
			matches: []string{"tcp"}, targetName: "", verdict: -2, // accept
		})
		under[1] = b.add(entrySpec{targetName: "", verdict: -1}) // policy drop
		// FORWARD empty, policy ACCEPT: hook and underflow share the entry.
		fw := b.add(entrySpec{targetName: "", verdict: -2})
		hooks[2], under[2] = fw, fw
		// OUTPUT empty, policy ACCEPT.
		out := b.add(entrySpec{targetName: "", verdict: -2})
		hooks[3], under[3] = out, out
		return hooks, under, 1<<1 | 1<<2 | 1<<3
	})

	table, err := parseLegacyTable(v4Parse, "filter", info, blob)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(table.Chains) != 3 {
		t.Fatalf("chains = %+v, want 3", table.Chains)
	}
	in := table.Chains[0]
	if in.Name != "INPUT" || !in.BuiltIn || in.Policy != "drop" || len(in.Rules) != 1 {
		t.Fatalf("INPUT wrong: %+v", in)
	}
	wantText := "-p tcp -s 192.0.2.0/24 [xt match tcp] accept"
	if in.Rules[0].Text != wantText || in.Rules[0].Rendered != "partial" {
		t.Fatalf("rule = %q (%s), want %q (partial)", in.Rules[0].Text, in.Rules[0].Rendered, wantText)
	}
	if table.Chains[1].Policy != "accept" || len(table.Chains[1].Rules) != 0 {
		t.Fatalf("FORWARD wrong: %+v", table.Chains[1])
	}
}

func TestLegacyUserChainAndForwardJump(t *testing.T) {
	var userStart uint32
	info, blob := buildFilterTable(t, func(b *blobBuilder) ([numHooks]uint32, [numHooks]uint32, uint32) {
		var hooks, under [numHooks]uint32
		// INPUT jumps forward to WPTEST, which is defined after it.
		jumpEntry := b.add(entrySpec{targetName: "", verdict: 0}) // patched below
		under[1] = b.add(entrySpec{targetName: "", verdict: -2})
		hooks[1] = jumpEntry
		// The user chain: ERROR marker naming it, one rule, implicit RETURN.
		b.add(entrySpec{targetName: "ERROR", errorName: "WPTEST"})
		userStart = uint32(len(b.buf))
		// The kernel stores a wildcard interface with its plus in the name.
		b.add(entrySpec{iniface: "eth+", proto: 17, targetName: "", verdict: -1})
		b.add(entrySpec{targetName: "", verdict: -5}) // implicit return
		// Patch the jump verdict with the user chain's real offset.
		binary.LittleEndian.PutUint32(b.buf[jumpEntry+112+32:], userStart)
		return hooks, under, 1 << 1
	})

	table, err := parseLegacyTable(v4Parse, "filter", info, blob)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(table.Chains) != 2 {
		t.Fatalf("chains = %+v, want INPUT and WPTEST", table.Chains)
	}
	in, user := table.Chains[0], table.Chains[1]
	if in.Rules[0].Text != "jump WPTEST" || in.Rules[0].Rendered != "full" {
		t.Fatalf("forward jump = %q (%s), want jump WPTEST (full)", in.Rules[0].Text, in.Rules[0].Rendered)
	}
	if user.Name != "WPTEST" || user.BuiltIn || user.Policy != "" {
		t.Fatalf("user chain wrong: %+v", user)
	}
	// The wildcard interface renders with the plus, and the implicit
	// trailing RETURN is omitted the way iptables-save omits it.
	if len(user.Rules) != 1 || user.Rules[0].Text != "-p udp -i eth+ drop" {
		t.Fatalf("user rules wrong: %+v", user.Rules)
	}
}

func TestLegacyInversionAndExactIface(t *testing.T) {
	info, blob := buildFilterTable(t, func(b *blobBuilder) ([numHooks]uint32, [numHooks]uint32, uint32) {
		var hooks, under [numHooks]uint32
		hooks[1] = b.add(entrySpec{
			proto: 17, inv: xtInvProto,
			iniface: "eth0", inifaceExact: true,
			targetName: "", verdict: -5,
		})
		under[1] = b.add(entrySpec{targetName: "", verdict: -2})
		return hooks, under, 1 << 1
	})
	table, err := parseLegacyTable(v4Parse, "filter", info, blob)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	want := "! -p udp -i eth0 return"
	if got := table.Chains[0].Rules[0]; got.Text != want || got.Rendered != "full" {
		t.Fatalf("rule = %q (%s), want %q (full)", got.Text, got.Rendered, want)
	}
}

func TestLegacyNamedTargetIsPartial(t *testing.T) {
	info, blob := buildFilterTable(t, func(b *blobBuilder) ([numHooks]uint32, [numHooks]uint32, uint32) {
		var hooks, under [numHooks]uint32
		hooks[1] = b.add(entrySpec{proto: 6, targetName: "REJECT"})
		under[1] = b.add(entrySpec{targetName: "", verdict: -2})
		return hooks, under, 1 << 1
	})
	table, err := parseLegacyTable(v4Parse, "filter", info, blob)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	want := "-p tcp [xt target REJECT]"
	if got := table.Chains[0].Rules[0]; got.Text != want || got.Rendered != "partial" {
		t.Fatalf("rule = %q (%s), want %q (partial)", got.Text, got.Rendered, want)
	}
}

func TestLegacyHostileBlobsFailLoudly(t *testing.T) {
	goodInfo, goodBlob := buildFilterTable(t, func(b *blobBuilder) ([numHooks]uint32, [numHooks]uint32, uint32) {
		var hooks, under [numHooks]uint32
		e := b.add(entrySpec{targetName: "", verdict: -2})
		hooks[1], under[1] = e, e
		return hooks, under, 1 << 1
	})

	corrupt := func(name string, mutate func(info *legacyInfo, blob []byte) []byte) {
		info := goodInfo
		blob := append([]byte(nil), goodBlob...)
		blob = mutate(&info, blob)
		if _, err := parseLegacyTable(v4Parse, "filter", info, blob); err == nil {
			t.Errorf("%s: hostile blob parsed without error", name)
		}
	}

	corrupt("truncated blob", func(info *legacyInfo, blob []byte) []byte {
		return blob[:len(blob)-8]
	})
	corrupt("zero next_offset loop", func(info *legacyInfo, blob []byte) []byte {
		binary.LittleEndian.PutUint16(blob[90:], 0)
		return blob
	})
	corrupt("target beyond entry", func(info *legacyInfo, blob []byte) []byte {
		binary.LittleEndian.PutUint16(blob[88:], 60000)
		return blob
	})
	corrupt("declared size mismatch", func(info *legacyInfo, blob []byte) []byte {
		info.size += 8
		return blob
	})
	corrupt("more entries than declared", func(info *legacyInfo, blob []byte) []byte {
		info.numEntries = 1
		return blob
	})
}

func TestLegacyHostileChainNameSanitized(t *testing.T) {
	info, blob := buildFilterTable(t, func(b *blobBuilder) ([numHooks]uint32, [numHooks]uint32, uint32) {
		var hooks, under [numHooks]uint32
		e := b.add(entrySpec{targetName: "", verdict: -2})
		hooks[1], under[1] = e, e
		b.add(entrySpec{targetName: "ERROR", errorName: "ev\x1bil"})
		b.add(entrySpec{targetName: "", verdict: -5})
		return hooks, under, 1 << 1
	})
	table, err := parseLegacyTable(v4Parse, "filter", info, blob)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(table.Chains) != 2 || table.Chains[1].Name != "ev?il" {
		t.Fatalf("hostile chain name not sanitized: %+v", table.Chains)
	}
	d := hostdoc.New("h", 1)
	d.Iptables = &hostdoc.IptablesSection{
		Section: hostdoc.Section{Status: hostdoc.StatusCollected},
		Sources: map[string]hostdoc.Section{"filter": {Status: hostdoc.StatusCollected}},
		Tables:  []hostdoc.IptTable{table},
	}
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, b)
}

func TestLegacyMaskText(t *testing.T) {
	cases := map[string]string{
		"\xff\xff\xff\x00": "24",
		"\xff\xff\xff\xff": "32",
		"\x00\x00\x00\x00": "0",
		"\xff\x00\xff\x00": "255.0.255.0", // non-contiguous stays raw
	}
	for in, want := range cases {
		if got := maskText([]byte(in)); got != want {
			t.Errorf("maskText(%x) = %q, want %q", in, got, want)
		}
	}
}
