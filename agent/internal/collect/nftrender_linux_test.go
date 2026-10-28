//go:build linux

package collect

// The renderer's address-prefix cases. nftables stores an address prefix as a
// payload load shorter than the field it starts in, so `ip saddr 10.88.0.0/16`
// arrives as a two-byte load at byte 12. Naming it is only safe under narrow
// conditions, and most of this file is the cases where naming it would be a
// guess and the raw form has to survive.
//
// The offsets under test are protocol facts, not preferences: IPv4 carries the
// source address at byte 12 and the destination at byte 16, four bytes each
// (RFC 791 section 3.1), and IPv6 carries them at bytes 8 and 24, sixteen bytes
// each (RFC 8200 section 3).

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// nhLoad is a network-header payload load into register 1.
func nhLoad(offset, length uint32) *expr.Payload {
	return &expr.Payload{
		OperationType: expr.PayloadLoad,
		DestRegister:  1,
		Base:          expr.PayloadBaseNetworkHeader,
		Offset:        offset,
		Len:           length,
	}
}

func eq(data ...byte) *expr.Cmp {
	return &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data}
}

// pinV4 and pinV6 are the `meta nfproto` match that tells an inet rule which
// IP version it is looking at. Without one, a network-header offset in an inet
// table means nothing on its own.
func pinV4() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(nftables.TableFamilyIPv4)}},
	}
}

func pinV6() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(nftables.TableFamilyIPv6)}},
	}
}

func join(groups ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// TestAddressPrefixRendering is the whole decision table in one place: which
// loads become a named field with a prefix length, and which stay in nft's raw
// form because naming them would be a guess.
func TestAddressPrefixRendering(t *testing.T) {
	cases := []struct {
		name   string
		family nftables.TableFamily
		exprs  []expr.Any
		want   string
		grade  string
	}{
		// The four forms the live fleet actually produces, measured on a
		// read-only copy of the production database taken 2026-08-16.
		{
			// An AlmaLinux 10 server, inet firewalld, filter_FORWARD_POLICIES. 0x0a58 is
			// 10.88, netavark's default subnet on that Podman host.
			name:   "real firewalld forward policy, both address prefixes",
			family: nftables.TableFamilyINet,
			exprs: join(pinV4(), []expr.Any{
				nhLoad(12, 2), eq(0x0a, 0x58),
				nhLoad(16, 2), eq(0x0a, 0x58),
				&expr.Verdict{Kind: expr.VerdictJump, Chain: "filter_FWD_trusted"},
			}),
			want:  "meta nfproto ipv4 ip saddr 10.88.0.0/16 ip daddr 10.88.0.0/16 jump filter_FWD_trusted",
			grade: "full",
		},
		{
			// The same server, inet netavark. The container publication rule that
			// names tcp/8096 in plain text and was filed unreadable only
			// because it also carries a source prefix (RECORD 4.51).
			name:   "real netavark publication rule",
			family: nftables.TableFamilyINet,
			exprs: join(pinV4(), []expr.Any{
				nhLoad(12, 2), eq(0x0a, 0x58),
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x1f, 0xa0}},
				&expr.Verdict{Kind: expr.VerdictJump, Chain: "NETAVARK-HOSTPORT-SETMARK"},
			}),
			want:  "meta nfproto ipv4 ip saddr 10.88.0.0/16 meta l4proto tcp tcp dport 8096 jump NETAVARK-HOSTPORT-SETMARK",
			grade: "full",
		},
		{
			// An Ubuntu 24.04 server running Docker, ip nat POSTROUTING. 0xac11 is 172.17, docker0's
			// default subnet. The family comes from the table, not a pin.
			name:   "real docker masquerade source prefix",
			family: nftables.TableFamilyIPv4,
			exprs: []expr.Any{
				nhLoad(12, 2), eq(0xac, 0x11),
				&expr.Counter{},
			},
			want:  "ip saddr 172.17.0.0/16 counter",
			grade: "full",
		},
		{
			// The AlmaLinux server, inet firewalld, the DHCPv6 client rule. Eight bytes
			// of a sixteen-byte field is a /64.
			name:   "real ipv6 link-local destination prefix",
			family: nftables.TableFamilyINet,
			exprs: join(pinV6(), []expr.Any{
				nhLoad(24, 8), eq(0xfe, 0x80, 0, 0, 0, 0, 0, 0),
				&expr.Verdict{Kind: expr.VerdictAccept},
			}),
			want:  "meta nfproto ipv6 ip6 daddr fe80::/64 accept",
			grade: "full",
		},
		{
			// The Ubuntu server, ip nat OUTPUT. A one-byte load at the
			// destination address, compared unequal. nft would print this as
			// `ip daddr != 127.0.0.0/8`, but this renderer names a prefix only
			// under equality, so it stays exact instead of being widened on a
			// reading nothing here tested.
			name:   "real loopback exclusion is not equality, stays raw",
			family: nftables.TableFamilyIPv4,
			exprs: []expr.Any{
				nhLoad(16, 1),
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x7f}},
				&expr.Counter{},
			},
			want:  "@nh,128,8 != 0x7f counter",
			grade: "full",
		},

		// Everything below is a load that must not be named.
		{
			name:   "starts mid field",
			family: nftables.TableFamilyIPv4,
			exprs:  []expr.Any{nhLoad(13, 2), eq(0x0a, 0x58)},
			want:   "@nh,104,16 0x0a58",
			grade:  "full",
		},
		{
			name:   "starts one byte before the field",
			family: nftables.TableFamilyIPv4,
			exprs:  []expr.Any{nhLoad(11, 2), eq(0x00, 0x0a)},
			want:   "@nh,88,16 0x000a",
			grade:  "full",
		},
		{
			name:   "runs past the end of the field into the next one",
			family: nftables.TableFamilyIPv4,
			exprs:  []expr.Any{nhLoad(12, 6), eq(0x0a, 0x58, 0, 0, 0x0a, 0x58)},
			want:   "@nh,96,48 0x0a5800000a58",
			grade:  "full",
		},
		{
			name:   "longer than the field",
			family: nftables.TableFamilyIPv4,
			exprs:  []expr.Any{nhLoad(12, 5), eq(0x0a, 0x58, 0, 0, 0)},
			want:   "@nh,96,40 0x0a58000000",
			grade:  "full",
		},
		{
			name:   "zero length",
			family: nftables.TableFamilyIPv4,
			exprs:  []expr.Any{nhLoad(12, 0), eq()},
			want:   "@nh,96,0 0x",
			grade:  "full",
		},
		{
			name:   "ordering comparison on a short load",
			family: nftables.TableFamilyIPv4,
			exprs: []expr.Any{
				nhLoad(12, 2),
				&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: []byte{0x0a, 0x58}},
			},
			want:  "@nh,96,16 >= 0x0a58",
			grade: "full",
		},
		{
			// An inet table sees both families. Byte 12 is the IPv4 source
			// address and also the middle of the IPv6 source address, and
			// nothing in the rule says which. This is the mistake the
			// accuracy rule is about: it looks like IPv4 and is not
			// evidence of it.
			name:   "inet with no family pinned",
			family: nftables.TableFamilyINet,
			exprs:  []expr.Any{nhLoad(12, 2), eq(0x0a, 0x58)},
			want:   "@nh,96,16 0x0a58",
			grade:  "full",
		},
		{
			// Byte 12 under IPv6 is four bytes into the source address, not
			// the start of any field.
			name:   "ipv4 source offset read as ipv6",
			family: nftables.TableFamilyIPv6,
			exprs:  []expr.Any{nhLoad(12, 2), eq(0x0a, 0x58)},
			want:   "@nh,96,16 0x0a58",
			grade:  "full",
		},
		{
			// A bitwise mask makes the comparison a masked one, which is how
			// nft encodes a prefix that is not a whole number of bytes. The
			// mask applies to the loaded bytes and not to the whole field, so
			// printing a field name beside it would misstate what is masked.
			name:   "masked short load keeps the raw form",
			family: nftables.TableFamilyIPv4,
			exprs: []expr.Any{
				nhLoad(12, 3),
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 3,
					Mask: []byte{0xff, 0xff, 0xf0}, Xor: []byte{0, 0, 0}},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x0a, 0x58, 0x00}},
			},
			want:  "@nh,96,24 & 0xfffff0 == 0x0a5800",
			grade: "full",
		},
		{
			// The comparison must describe the same number of bytes the load
			// put in the register. A mismatch is not something this renderer
			// can reason about.
			name:   "comparison width does not match the load",
			family: nftables.TableFamilyIPv4,
			exprs:  []expr.Any{nhLoad(12, 2), eq(0x0a, 0x58, 0x00)},
			want:   "@nh,96,16 0x0a5800",
			grade:  "full",
		},
		{
			// The transport header has no address field. Offsets 0 and 2 are
			// already named ports; anything else stays raw.
			name:   "transport header load is never an address",
			family: nftables.TableFamilyIPv4,
			exprs: []expr.Any{
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 12, Len: 2},
				eq(0x0a, 0x58),
			},
			want:  "@th,96,16 0x0a58",
			grade: "full",
		},
		{
			name:   "link layer load is never an address",
			family: nftables.TableFamilyIPv4,
			exprs: []expr.Any{
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 12, Len: 2},
				eq(0x0a, 0x58),
			},
			want:  "@ll,96,16 0x0a58",
			grade: "full",
		},

		// Prefix widths that are legitimate and must be named.
		{
			name:   "one byte of an ipv4 source is a /8",
			family: nftables.TableFamilyIPv4,
			exprs:  []expr.Any{nhLoad(12, 1), eq(0x0a)},
			want:   "ip saddr 10.0.0.0/8",
			grade:  "full",
		},
		{
			name:   "three bytes of an ipv4 destination is a /24",
			family: nftables.TableFamilyIPv4,
			exprs:  []expr.Any{nhLoad(16, 3), eq(0xc0, 0x00, 0x02)},
			want:   "ip daddr 192.0.2.0/24",
			grade:  "full",
		},
		{
			name:   "one byte of an ipv6 source is a /8",
			family: nftables.TableFamilyIPv6,
			exprs:  []expr.Any{nhLoad(8, 1), eq(0xfe)},
			want:   "ip6 saddr fe00::/8",
			grade:  "full",
		},
		{
			name:   "six bytes of an ipv6 source is a /48",
			family: nftables.TableFamilyIPv6,
			exprs:  []expr.Any{nhLoad(8, 6), eq(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01)},
			want:   "ip6 saddr 2001:db8:1::/48",
			grade:  "full",
		},
		{
			name:   "fifteen bytes of an ipv6 destination is a /120",
			family: nftables.TableFamilyIPv6,
			exprs:  []expr.Any{nhLoad(24, 15), eq(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)},
			want:   "ip6 daddr 2001:db8::/120",
			grade:  "full",
		},
		{
			// An IPv6 load starting at byte 24 that runs past byte 39 has left
			// the destination address.
			name:   "ipv6 destination load running past the field",
			family: nftables.TableFamilyIPv6,
			exprs:  []expr.Any{nhLoad(24, 17), eq(make([]byte, 17)...)},
			want:   "@nh,192,136 0x0000000000000000000000000000000000",
			grade:  "full",
		},

		// Proof that what already worked still works, byte for byte.
		{
			name:   "full ipv4 source address",
			family: nftables.TableFamilyIPv4,
			exprs: []expr.Any{
				nhLoad(12, 4), eq(192, 0, 2, 1),
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
			want:  "ip saddr 192.0.2.1 drop",
			grade: "full",
		},
		{
			name:   "full ipv4 destination address",
			family: nftables.TableFamilyIPv4,
			exprs:  []expr.Any{nhLoad(16, 4), eq(198, 51, 100, 9)},
			want:   "ip daddr 198.51.100.9",
			grade:  "full",
		},
		{
			name:   "full ipv6 source address",
			family: nftables.TableFamilyIPv6,
			exprs:  []expr.Any{nhLoad(8, 16), eq(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)},
			want:   "ip6 saddr 2001:db8::1",
			grade:  "full",
		},
		{
			name:   "full ipv6 destination address",
			family: nftables.TableFamilyIPv6,
			exprs:  []expr.Any{nhLoad(24, 16), eq(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)},
			want:   "ip6 daddr 2001:db8::2",
			grade:  "full",
		},
		{
			// An IPv4-mapped IPv6 address is a legal thing to write in an
			// ip6 rule, and net.IP.String prints one as a bare dotted quad,
			// which reads as an IPv4 rule. It is an IPv6 rule and has to look
			// like one.
			name:   "ipv4 mapped ipv6 address stays an ipv6 address",
			family: nftables.TableFamilyIPv6,
			exprs:  []expr.Any{nhLoad(8, 16), eq(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1)},
			want:   "ip6 saddr ::ffff:192.0.2.1",
			grade:  "full",
		},
		{
			name:   "ipv4 mapped ipv6 prefix stays an ipv6 address",
			family: nftables.TableFamilyIPv6,
			exprs:  []expr.Any{nhLoad(24, 12), eq(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff)},
			want:   "ip6 daddr ::ffff:0.0.0.0/96",
			grade:  "full",
		},
		{
			name:   "ipv4 protocol field",
			family: nftables.TableFamilyIPv4,
			exprs:  []expr.Any{nhLoad(9, 1), eq(6)},
			want:   "ip protocol tcp",
			grade:  "full",
		},
		{
			name:   "ipv6 next header field",
			family: nftables.TableFamilyIPv6,
			exprs:  []expr.Any{nhLoad(6, 1), eq(17)},
			want:   "ip6 nexthdr udp",
			grade:  "full",
		},
		{
			name:   "transport ports still render by name",
			family: nftables.TableFamilyIPv4,
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x35}},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x16}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			want:  "meta l4proto tcp tcp sport 53 tcp dport 22 accept",
			grade: "full",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, grade := renderRule(tc.family, tc.exprs)
			if got != tc.want || grade != tc.grade {
				t.Errorf("got %q (%s)\nwant %q (%s)", got, grade, tc.want, tc.grade)
			}
		})
	}
}

// TestAddressPrefixNeedsTheFamilyToStayPinned guards the register-invalidation
// path from the other direction: an expression this renderer does not model
// clears the register contexts, and a prefix load after it must still be named
// from the family, not from a stale context.
func TestAddressPrefixSurvivesRegisterInvalidation(t *testing.T) {
	got, grade := renderRule(nftables.TableFamilyIPv4, []expr.Any{
		&expr.Fib{Register: 1, ResultADDRTYPE: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
		nhLoad(12, 2), eq(0x0a, 0x58),
		&expr.Verdict{Kind: expr.VerdictDrop},
	})
	want := "[expr Fib] [cmp on unknown register] ip saddr 10.88.0.0/16 drop"
	if got != want || grade != "partial" {
		t.Fatalf("got %q (%s), want %q (partial)", got, grade, want)
	}
}

// TestAddressPrefixIsNotInventedInsideAMeta pins that the prefix path only
// ever reads a payload load. A meta register carrying an address-shaped value
// must not pick up a field name.
func TestAddressPrefixOnlyAppliesToPayloadLoads(t *testing.T) {
	got, grade := renderRule(nftables.TableFamilyIPv4, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x0a, 0x58}},
	})
	want := "meta mark 0x0a58"
	if got != want || grade != "full" {
		t.Fatalf("got %q (%s), want %q (full)", got, grade, want)
	}
}
