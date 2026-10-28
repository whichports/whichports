// This file is the interface-addresses collector: which addresses the kernel
// says this host holds, as distinct from which addresses something is
// listening on. The sockets collector answers the second question and cannot
// answer the first, because on an ordinary server every service binds the
// wildcard and the wildcard names no address at all.
//
// **The read is rtnetlink, through the standard library, and there is no exec
// here** (docs/PRODUCT.md 4e). net.Interfaces sends RTM_GETLINK and
// Interface.Addrs sends RTM_GETADDR, both via syscall.NetlinkRIB, read in the
// Go 1.26 source at src/net/interface_linux.go on 2026-08-17. That is the same
// interface iproute2 uses, and it is the same class of read the nftables
// collector already makes. It is worth saying why it is not /proc like the
// sockets collector: **the kernel publishes no per-interface IPv4 address list
// under /proc.** /proc/net/if_inet6 exists for v6 and there is no v4
// counterpart, so a /proc-only version of this collector could report v6 and
// would have to stay silent about v4, which is the family every host on the
// fleet actually has.
//
// Each Interface.Addrs call dumps the whole address table and filters it by
// interface index, so this collector makes one dump per interface rather than
// one in total. That is accepted: it is a read of kernel memory once every
// fifteen minutes, and the alternative is parsing netlink by hand in a process
// that runs as root on other people's machines.
package collect

import (
	"errors"
	"net"
	"os"
	"sort"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// sharedAddressSpace is RFC 6598 carrier-grade NAT space. It is shared between
// a carrier's customers by definition, so no single operator holds one of its
// addresses. Named explicitly because net.IP.IsPrivate does not cover it, and
// the registry names it explicitly for the same reason
// (controlplane/app/authz.py, SHARED_ADDRESS_SPACE).
var sharedAddressSpace = &net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)}

// linkLister and addrLister are the two kernel reads, taken as arguments so
// the shaping and the failure handling below are testable without a live host
// and without root. The exported entry point supplies the real ones and
// nothing else ever should.
type (
	linkLister func() ([]net.Interface, error)
	addrLister func(net.Interface) ([]net.Addr, error)
)

// CollectInterfaceAddresses reads the host's interfaces and their addresses
// and returns the section. It never returns nil, and a read that failed comes
// back as a status saying so rather than as a host with no addresses.
func CollectInterfaceAddresses() *hostdoc.InterfaceAddressesSection {
	return collectInterfaceAddresses(net.Interfaces, interfaceAddrs)
}

// interfaceAddrs adapts the method to the function type. A method value on a
// loop variable would work too; this is one line and says what it is.
func interfaceAddrs(ifi net.Interface) ([]net.Addr, error) { return ifi.Addrs() }

// collectInterfaceAddresses is the whole collector, with the kernel injected.
//
// The verdict is strict on purpose. One interface whose addresses could not be
// read makes the whole section say so, because the payload here is a single
// list and a short list that reads as complete is exactly the false all-quiet
// RECORD.md 4.46 is about. The addresses that were read are still carried
// beside the failure: they are real, and dropping them to make the output tidy
// would lose evidence.
//
// Interface flags are deliberately not consulted. An address is assigned or it
// is not, and whether anything can reach it is the prober's question and not
// this document's (PRODUCT.md 4e principle 4).
func collectInterfaceAddresses(links linkLister, addrs addrLister) *hostdoc.InterfaceAddressesSection {
	// Never nil, so "collected and empty" survives into the JSON as an empty
	// list rather than becoming indistinguishable from "not collected".
	sec := &hostdoc.InterfaceAddressesSection{Addresses: []hostdoc.InterfaceAddress{}}

	interfaces, err := links()
	if err != nil {
		sec.Section = netlinkVerdict(err)
		return sec
	}

	verdict := hostdoc.Section{Status: hostdoc.StatusCollected}
	for _, ifi := range interfaces {
		list, err := addrs(ifi)
		if err != nil {
			verdict = worseVerdict(verdict, netlinkVerdict(err))
			continue
		}
		// An interface name is chosen on the host and this document is printed
		// on an operator's terminal in stdout mode (RECORD.md 4.14).
		name := sanitizeName(ifi.Name)
		for _, addr := range list {
			ip := addressOf(addr)
			if !reportableAddress(ip) {
				continue
			}
			sec.Addresses = append(sec.Addresses, newInterfaceAddress(name, ip))
		}
	}

	sortInterfaceAddresses(sec.Addresses)
	sec.Section = verdict
	return sec
}

// newInterfaceAddress renders one entry. The family is derived from the
// address and the address is rendered from the same value, so the two can
// never disagree, which is what the control plane checks when it matches
// (controlplane/app/authz.py).
//
// A v4-mapped v6 address comes out as a plain v4 address with family v4. The
// kernel does not assign those to interfaces, so this is a shape that should
// never arrive; the point is that if it ever does, the address text and the
// family still agree. Note this is the opposite choice from decodeV6 in the
// sockets collector, and for the opposite reason: there the family came from
// which /proc file the row was in, so the address had to be rendered to match
// it, and here the address is all there is.
func newInterfaceAddress(iface string, ip net.IP) hostdoc.InterfaceAddress {
	family := "v6"
	rendered := ip
	if v4 := ip.To4(); v4 != nil {
		family = "v4"
		rendered = v4
	}
	return hostdoc.InterfaceAddress{
		Interface: iface,
		Family:    family,
		Address:   rendered.String(),
		Global:    addressIsGlobal(ip),
	}
}

// addressOf pulls the address out of one net.Addr. Linux returns *net.IPNet,
// but Addr is an interface, so both address shapes the standard library can
// produce are handled and anything else yields nil rather than a panic.
func addressOf(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}

// reportableAddress decides what reaches the document.
//
// **Loopback and link-local are left out, and that is a decision worth stating
// rather than a filter.** Every host has 127.0.0.1 and a fe80::/10 address on
// every interface, so they distinguish no host from any other, and the
// registry refuses both by name as probe targets, so an entry carrying one
// could never match anything. A link-local address is only meaningful together
// with the interface it is on, and an address that needs a zone index to mean
// anything is refused as a target for that exact reason.
//
// **Private and carrier-NAT addresses are kept**, marked not global. They are
// the NAT evidence: a host whose only address is 10.0.0.5 while its report
// arrives from a public address is a host behind NAT, and the control plane
// can only see that if the private address is in the document. Keeping them
// authorises nothing, because the registry refuses them as targets at the
// door.
//
// The precedent for filtering at all rather than reporting everything is the
// sockets collector, which drops established TCP and connected UDP rows on the
// same reasoning: they are not something the internet can newly reach.
func reportableAddress(ip net.IP) bool {
	// Not 4 or 16 bytes: not an address. This has to come first, because the
	// classifier methods below silently answer false for a malformed value
	// instead of rejecting it.
	if ip.To16() == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() {
		return false
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	return true
}

// addressIsGlobal is the agent's own reading of whether an address is globally
// routable unicast. **Nothing decides anything from it**: the control plane
// re-derives probeability from the address text itself, and a test there pins
// that this flag changes no decision either way. It is here so a person
// reading the document at a terminal can see which of a host's addresses is
// the public one.
func addressIsGlobal(ip net.IP) bool {
	if !reportableAddress(ip) {
		return false
	}
	// IsGlobalUnicast is true for private addresses, so IsPrivate is a
	// separate question and not a subset of it. IsPrivate covers 10/8,
	// 172.16/12, 192.168/16 and fc00::/7, and it does not cover carrier-NAT
	// space, which is why that is checked by hand below.
	if ip.IsPrivate() || !ip.IsGlobalUnicast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return !sharedAddressSpace.Contains(v4)
	}
	return true
}

// netlinkVerdict maps a failed kernel read to a typed verdict. A denial is
// separated out because it is actionable and a broken read is not, the same
// distinction fileVerdict makes for the file-reading collectors.
func netlinkVerdict(err error) hostdoc.Section {
	if errors.Is(err, os.ErrPermission) {
		return hostdoc.Section{
			Status: hostdoc.StatusPermissionDenied,
			Cause:  hostdoc.CausePermission,
		}
	}
	return hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseNetlink}
}

// worseVerdict returns the more serious of two verdicts, so a single failure
// anywhere survives to the section status. Permission outranks a read failure,
// which is the precedence aggregateSources already uses.
func worseVerdict(a, b hostdoc.Section) hostdoc.Section {
	if verdictRank(b) > verdictRank(a) {
		return b
	}
	return a
}

func verdictRank(s hostdoc.Section) int {
	switch s.Status {
	case hostdoc.StatusPermissionDenied:
		return 2
	case hostdoc.StatusReadError:
		return 1
	default:
		return 0
	}
}

// sortInterfaceAddresses orders the list so two runs over the same host state
// produce byte-identical documents, the same reason sortSockets exists. Family
// first, then interface, then the address text, which together are a total key
// for any two entries that are not identical.
func sortInterfaceAddresses(list []hostdoc.InterfaceAddress) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Family != list[j].Family {
			return list[i].Family < list[j].Family
		}
		if list[i].Interface != list[j].Interface {
			return list[i].Interface < list[j].Interface
		}
		return list[i].Address < list[j].Address
	})
}
