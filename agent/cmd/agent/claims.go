package main

import (
	"encoding/json"
	"net/netip"
	"sort"

	"github.com/whichports/whichports/agent/internal/report"
)

// claimedAddresses is the public addresses on this host's interfaces, read
// out of the document the agent just collected, so what our prober API is
// told is a subset of what the host's own control plane is told
// (report.ProveToProber).
//
// Filtering here is data minimisation, never a decision. A private,
// loopback or link-local address could never be probed from outside, so it
// is not sent. The filter reads the address text itself rather than the
// document's own `global` bit, which nothing is allowed to decide from
// (hostdoc.InterfaceAddress), and the API decides again from the text
// whatever arrives. A document that cannot be read yields no addresses, and
// then nothing is sent at all.
//
// It lives here and not in internal/report because that package imports no
// JSON library at all (the safety scan), and this reads the agent's own
// output, never a response.
func claimedAddresses(document []byte) []netip.Addr {
	var doc struct {
		InterfaceAddresses *struct {
			Addresses []struct {
				Address string `json:"address"`
			} `json:"addresses"`
		} `json:"interface_addresses"`
	}
	if err := json.Unmarshal(document, &doc); err != nil || doc.InterfaceAddresses == nil {
		return nil
	}
	seen := map[netip.Addr]bool{}
	var claimed []netip.Addr
	for _, entry := range doc.InterfaceAddresses.Addresses {
		addr, err := netip.ParseAddr(entry.Address)
		if err != nil || addr.Zone() != "" {
			continue
		}
		if addr.Is4In6() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
			continue
		}
		if !seen[addr] {
			seen[addr] = true
			claimed = append(claimed, addr)
		}
	}
	sort.Slice(claimed, func(i, j int) bool { return claimed[i].Less(claimed[j]) })
	if len(claimed) > report.MaxClaimedAddresses {
		claimed = claimed[:report.MaxClaimedAddresses]
	}
	return claimed
}
