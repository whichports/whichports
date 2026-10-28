package collect

// Fuzz targets for every parser that eats host-controlled bytes. The shared
// property is the collector contract itself: a parser must never panic, and
// whatever it accepts must survive the document's fail-closed marshaller and
// stay terminal-safe. In CI these run once over their seed corpus like any
// test; locally, `go test -fuzz=FuzzX ./internal/collect` digs deeper.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// marshalOrFail asserts the accepted-input half of the property: parse
// results always make a valid, terminal-safe document.
func marshalOrFail(t *testing.T, mutate func(d *hostdoc.Document)) {
	t.Helper()
	d := hostdoc.New("h", 1)
	mutate(d)
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatalf("collector output failed the document contract: %v", err)
	}
	assertTerminalSafe(t, b)
}

func FuzzParseProcNet(f *testing.F) {
	f.Add("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0\n")
	f.Add("   0: 0100007F:1538 0100007F:C1B4 01 0 0 0 0 0 34567 1 0\n")
	f.Add("garbage\n\x00\xff\x1b[31m\n")
	f.Fuzz(func(t *testing.T, content string) {
		for _, src := range procNetSources {
			socks, err := parseProcNet(content, src)
			if err != nil {
				continue
			}
			listening := make([]hostdoc.ListeningSocket, 0, len(socks))
			for _, ps := range socks {
				listening = append(listening, ps.sock)
			}
			sortSockets(listening)
			marshalOrFail(t, func(d *hostdoc.Document) {
				d.Sockets = &hostdoc.SocketsSection{
					Section:   hostdoc.Section{Status: hostdoc.StatusCollected},
					Listening: listening,
				}
			})
		}
	})
}

func FuzzParsePasswd(f *testing.F) {
	// The passwd file is host-provided bytes like any other input here, and
	// every name it yields ends up on a socket the document prints. The
	// property is the shared one: whatever the parser accepts must survive
	// the fail-closed marshaller, in-range uids and bounded sanitized names
	// included, and stay terminal-safe.
	f.Add("root:x:0:0:root:/root:/bin/bash\ncaddy:x:991:991::/var/lib/caddy:/usr/sbin/nologin\n")
	f.Add("broken\nnouid:x:notanumber:1::/:/bin/sh\nweb:x:80:80::/var/www:/usr/sbin/nologin\n")
	f.Add("ev\x1b[31mil:x:80:80::/:/bin/sh\n\x00\xff\n")
	f.Add("dup:x:5:5::/:/bin/sh\nother:x:5:5::/:/bin/sh\nhuge:x:99999999999:1::/:/bin/sh\n")
	f.Fuzz(func(t *testing.T, content string) {
		names, verdict := parsePasswd(content)
		if verdict.Status != hostdoc.StatusCollected {
			return
		}
		listening := make([]hostdoc.ListeningSocket, 0, len(names))
		for uid, name := range names {
			u := uid
			listening = append(listening, hostdoc.ListeningSocket{
				Protocol: "tcp", Family: "v4", BindAddress: "0.0.0.0",
				Port: 22, OwnerUID: &u, OwnerName: name,
			})
		}
		sortSockets(listening)
		marshalOrFail(t, func(d *hostdoc.Document) {
			d.Sockets = &hostdoc.SocketsSection{
				Section:   hostdoc.Section{Status: hostdoc.StatusCollected},
				Listening: listening,
			}
		})
	})
}

func FuzzParseLegacyTable(f *testing.F) {
	// Seed with a real minimal table built the way the kernel lays it out.
	var b blobBuilder
	e := b.add(entrySpec{targetName: "", verdict: -2})
	b.add(entrySpec{targetName: "ERROR", errorName: "ERROR"})
	f.Add(b.buf, uint32(e), uint32(e))
	f.Add([]byte("\x00\x01\x02"), uint32(0), uint32(0))
	f.Fuzz(func(t *testing.T, blob []byte, hook1, under1 uint32) {
		info := legacyInfo{
			validHooks: 1 << 1,
			size:       uint32(len(blob)),
			numEntries: 1 << 19,
		}
		info.hookEntry[1] = hook1
		info.underflow[1] = under1
		for _, fam := range []legacyFamily{v4Parse, v6Parse} {
			table, err := parseLegacyTable(fam, "filter", info, blob)
			if err != nil {
				continue
			}
			marshalOrFail(t, func(d *hostdoc.Document) {
				d.Iptables = &hostdoc.IptablesSection{
					Section: hostdoc.Section{Status: hostdoc.StatusCollected},
					Sources: map[string]hostdoc.Section{"filter": {Status: hostdoc.StatusCollected}},
					Tables:  []hostdoc.IptTable{table},
				}
			})
		}
	})
}

func FuzzParseZoneXML(f *testing.F) {
	f.Add([]byte(`<?xml version="1.0"?><zone target="ACCEPT"><service name="ssh"/><port port="80" protocol="tcp"/></zone>`))
	f.Add([]byte(`<!DOCTYPE zone [<!ENTITY x "y">]><zone><service name="&x;"/></zone>`))
	f.Add([]byte("\x00\x01 not xml"))
	f.Fuzz(func(t *testing.T, content []byte) {
		x, ok := parseZoneXML(content)
		if !ok {
			return
		}
		z := mergeZone(hostdoc.FirewalldZone{File: "f.xml", Origin: "etc", Name: "f", Parsed: true}, x)
		marshalOrFail(t, func(d *hostdoc.Document) {
			d.Firewalld = &hostdoc.FirewalldSection{
				Section: hostdoc.Section{Status: hostdoc.StatusCollected},
				Sources: map[string]hostdoc.Section{"etc_zones": {Status: hostdoc.StatusCollected}},
				Zones:   []hostdoc.FirewalldZone{z},
			}
		})
	})
}

func FuzzReadKeyValueFile(f *testing.F) {
	f.Add("ENABLED=yes\nLOGLEVEL=low\n")
	f.Add("A=\"quoted\"\n# comment\n\x00garbage\n")
	f.Fuzz(func(t *testing.T, content string) {
		dir := t.TempDir()
		p := filepath.Join(dir, "conf")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Skip()
		}
		conf, verdict := readKeyValueFile(p)
		if verdict.Status != hostdoc.StatusCollected {
			return
		}
		marshalOrFail(t, func(d *hostdoc.Document) {
			d.Ufw = &hostdoc.UfwSection{
				Section: hostdoc.Section{Status: hostdoc.StatusCollected},
				Sources: map[string]hostdoc.Section{"ufw.conf": {Status: hostdoc.StatusCollected}},
				Conf:    conf,
			}
		})
	})
}

func FuzzRenderNftRule(f *testing.F) {
	// The renderer consumes decoded expressions, not raw bytes, so the fuzz
	// lever here is the comment TLV parser plus name sanitisation.
	f.Add([]byte{0x00, 0x03, 'h', 'i', 0x00})
	f.Add([]byte{0x00, 0xFF, 'x'})
	f.Fuzz(func(t *testing.T, userData []byte) {
		c := sanitizeName(ruleComment(userData))
		marshalOrFail(t, func(d *hostdoc.Document) {
			d.Nftables = &hostdoc.NftablesSection{
				Section: hostdoc.Section{Status: hostdoc.StatusCollected},
				Tables: []hostdoc.NftTable{{Family: "inet", Name: "t", Chains: []hostdoc.NftChain{{
					Name:  "c",
					Rules: []hostdoc.NftRule{{Text: "accept", Rendered: "full", Comment: c}},
				}}}},
			}
		})
	})
}
