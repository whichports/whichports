package collect

// The interface-addresses collector. The two kernel reads are injected, so
// every shape below is exercised without a live host and without root, the
// same way the /proc collectors are exercised against fixture trees.
//
// What is being proved here, in order of how much it would cost to get wrong:
//
//   - a read that failed is never reported as a host with no addresses. That
//     is the false all-quiet RECORD.md 4.46 is about, and it is what would
//     turn "we could not look" into "this machine holds nothing"
//   - the family always agrees with the address, because the control plane
//     matches on both and a document that disagrees with itself proves nothing
//   - loopback and link-local never reach the document
//   - the output is deterministic, so two runs over one host state produce
//     byte-identical documents

import (
	"errors"
	"net"
	"os"
	"reflect"
	"syscall"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// fakeHost builds the two injected readers from a plain description of a
// host: interface name to address list, plus optional per-interface errors.
type fakeHost struct {
	order     []string
	addresses map[string][]net.Addr
	addrErr   map[string]error
	linkErr   error
}

func (f fakeHost) links() ([]net.Interface, error) {
	if f.linkErr != nil {
		return nil, f.linkErr
	}
	out := make([]net.Interface, 0, len(f.order))
	for i, name := range f.order {
		out = append(out, net.Interface{Index: i + 1, Name: name})
	}
	return out, nil
}

func (f fakeHost) addrs(ifi net.Interface) ([]net.Addr, error) {
	if err, ok := f.addrErr[ifi.Name]; ok {
		return nil, err
	}
	return f.addresses[ifi.Name], nil
}

// cidr turns "192.0.2.1/24" into the *net.IPNet the kernel read returns. It
// fails the test on a typo rather than silently yielding nothing.
func cidr(t *testing.T, s string) net.Addr {
	t.Helper()
	ip, network, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("bad test address %q: %v", s, err)
	}
	return &net.IPNet{IP: ip, Mask: network.Mask}
}

func host(t *testing.T, addresses map[string][]string) fakeHost {
	t.Helper()
	f := fakeHost{addresses: map[string][]net.Addr{}, addrErr: map[string]error{}}
	for name, list := range addresses {
		f.order = append(f.order, name)
		for _, s := range list {
			f.addresses[name] = append(f.addresses[name], cidr(t, s))
		}
	}
	return f
}

func collectFrom(f fakeHost) *hostdoc.InterfaceAddressesSection {
	return collectInterfaceAddresses(f.links, f.addrs)
}

// addressStrings is what most assertions below compare against.
func addressStrings(sec *hostdoc.InterfaceAddressesSection) []string {
	out := make([]string, 0, len(sec.Addresses))
	for _, a := range sec.Addresses {
		out = append(out, a.Address)
	}
	return out
}

func TestAGlobalAddressIsReported(t *testing.T) {
	f := host(t, map[string][]string{"eth0": {"185.199.108.153/24"}})
	sec := collectFrom(f)
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %+v, want collected", sec.Section)
	}
	want := []hostdoc.InterfaceAddress{
		{Interface: "eth0", Family: "v4", Address: "185.199.108.153", Global: true},
	}
	if !reflect.DeepEqual(sec.Addresses, want) {
		t.Fatalf("addresses = %+v, want %+v", sec.Addresses, want)
	}
}

func TestTheFamilyComesFromTheAddress(t *testing.T) {
	f := host(t, map[string][]string{
		"eth0": {"185.199.108.153/24", "2606:50c0:8000::153/64"},
	})
	sec := collectFrom(f)
	got := map[string]string{}
	for _, a := range sec.Addresses {
		got[a.Address] = a.Family
	}
	want := map[string]string{
		"185.199.108.153":     "v4",
		"2606:50c0:8000::153": "v6",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("families = %+v, want %+v", got, want)
	}
}

func TestLoopbackAndLinkLocalNeverReachTheDocument(t *testing.T) {
	// Every host has these. They prove nothing about which addresses this
	// machine holds on the internet, and the registry refuses both by name,
	// so an entry could never match anything anyway.
	f := host(t, map[string][]string{
		"lo":   {"127.0.0.1/8", "::1/128"},
		"eth0": {"169.254.10.1/16", "fe80::1/64", "185.199.108.153/24"},
	})
	got := addressStrings(collectFrom(f))
	if !reflect.DeepEqual(got, []string{"185.199.108.153"}) {
		t.Fatalf("addresses = %v, want only the global one", got)
	}
}

func TestAPrivateAddressIsReportedAndMarkedNotGlobal(t *testing.T) {
	// This is the NAT evidence. A host whose only address is 10.0.0.5 while
	// its report arrives from a public address is a host behind NAT, and the
	// control plane can only see that if the private address is in the
	// document. It authorises nothing: the registry refuses a private address
	// as a target at the door.
	f := host(t, map[string][]string{"eth0": {"10.0.0.5/24"}})
	sec := collectFrom(f)
	want := []hostdoc.InterfaceAddress{
		{Interface: "eth0", Family: "v4", Address: "10.0.0.5", Global: false},
	}
	if !reflect.DeepEqual(sec.Addresses, want) {
		t.Fatalf("addresses = %+v, want %+v", sec.Addresses, want)
	}
}

func TestWhatCountsAsGlobal(t *testing.T) {
	// The classification, pinned. It is informational only, and the test that
	// proves nothing decides anything from it is on the control-plane side
	// (tests/test_authz.py). Pinned here anyway, because a flag a person
	// reads at a terminal still has to be right.
	cases := map[string]bool{
		"185.199.108.153/24":     true,
		"2606:50c0:8000::153/64": true,
		"10.0.0.5/8":             false,
		"172.16.0.1/12":          false,
		"192.168.1.1/24":         false,
		"100.64.0.1/10":          false, // carrier NAT, shared with strangers
		"fc00::1/7":              false, // unique local
		"fd00::1/8":              false,
		"169.254.1.1/16":         false, // excluded entirely, checked below
		"127.0.0.1/8":            false,
		"::1/128":                false,
		"fe80::1/64":             false,
	}
	for address, wantGlobal := range cases {
		ip, _, err := net.ParseCIDR(address)
		if err != nil {
			t.Fatalf("bad test address %q: %v", address, err)
		}
		if got := addressIsGlobal(ip); got != wantGlobal {
			t.Errorf("addressIsGlobal(%s) = %v, want %v", address, got, wantGlobal)
		}
	}
}

func TestAnUnreadableLinkTableIsNotAHostWithNoAddresses(t *testing.T) {
	// The finding that matters. A failed read reported as an empty list would
	// say "this machine holds no addresses", which is a claim, and a false
	// one.
	f := fakeHost{linkErr: errors.New("netlink went away")}
	sec := collectFrom(f)
	if sec.Status != hostdoc.StatusReadError || sec.Cause != hostdoc.CauseNetlink {
		t.Fatalf("section = %+v, want read_error/netlink", sec.Section)
	}
	if len(sec.Addresses) != 0 {
		t.Fatalf("a failed read must carry no addresses, got %+v", sec.Addresses)
	}
}

func TestADeniedLinkTableSaysDenied(t *testing.T) {
	f := fakeHost{linkErr: &net.OpError{Op: "route", Err: syscall.EPERM}}
	sec := collectFrom(f)
	if sec.Status != hostdoc.StatusPermissionDenied || sec.Cause != hostdoc.CausePermission {
		t.Fatalf("section = %+v, want permission_denied/permission", sec.Section)
	}
}

func TestOneUnreadableInterfaceMakesTheWholeListIncomplete(t *testing.T) {
	// RECORD.md 4.46, the rule-file mtimes shape: one readable source is not
	// enough to call an incomplete list complete. The addresses that were
	// read stay, because they are real, and the status says the list is short.
	f := host(t, map[string][]string{
		"eth0": {"185.199.108.153/24"},
		"eth1": {},
	})
	f.addrErr["eth1"] = &net.OpError{Op: "route", Err: syscall.EACCES}
	sec := collectFrom(f)
	if sec.Status != hostdoc.StatusPermissionDenied || sec.Cause != hostdoc.CausePermission {
		t.Fatalf("section = %+v, want permission_denied/permission", sec.Section)
	}
	if !reflect.DeepEqual(addressStrings(sec), []string{"185.199.108.153"}) {
		t.Fatalf("the readable addresses must survive, got %v", addressStrings(sec))
	}
}

func TestAnInterfaceReadErrorIsNotADenial(t *testing.T) {
	f := host(t, map[string][]string{"eth0": {"185.199.108.153/24"}, "eth1": {}})
	f.addrErr["eth1"] = errors.New("netlink parse failed")
	sec := collectFrom(f)
	if sec.Status != hostdoc.StatusReadError || sec.Cause != hostdoc.CauseNetlink {
		t.Fatalf("section = %+v, want read_error/netlink", sec.Section)
	}
}

func TestAPermissionDenialOutranksAParseFailure(t *testing.T) {
	// Same precedence aggregateSources uses: the actionable answer wins.
	f := host(t, map[string][]string{"eth0": {}, "eth1": {}})
	f.addrErr["eth0"] = errors.New("netlink parse failed")
	f.addrErr["eth1"] = os.ErrPermission
	sec := collectFrom(f)
	if sec.Status != hostdoc.StatusPermissionDenied {
		t.Fatalf("status = %q, want permission_denied", sec.Status)
	}
}

func TestAHostWithNoAddressesAtAllIsAMeasuredAnswer(t *testing.T) {
	f := host(t, map[string][]string{"lo": {"127.0.0.1/8"}})
	sec := collectFrom(f)
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("section = %+v, want collected", sec.Section)
	}
	if sec.Addresses == nil {
		t.Fatal("collected and empty must be an empty list, never nil, or the JSON loses the distinction")
	}
	if len(sec.Addresses) != 0 {
		t.Fatalf("addresses = %+v, want none", sec.Addresses)
	}
}

func TestTheOrderIsDeterministic(t *testing.T) {
	// Two runs over one host state must produce byte-identical documents, so
	// the control plane's diffing sees real changes and not reordering.
	one := host(t, map[string][]string{
		"eth1": {"185.199.109.153/24", "2606:50c0:8000::153/64"},
		"eth0": {"185.199.108.153/24"},
	})
	two := fakeHost{
		order:     []string{"eth0", "eth1"},
		addresses: map[string][]net.Addr{},
		addrErr:   map[string]error{},
	}
	two.addresses["eth0"] = []net.Addr{cidr(t, "185.199.108.153/24")}
	two.addresses["eth1"] = []net.Addr{
		cidr(t, "2606:50c0:8000::153/64"),
		cidr(t, "185.199.109.153/24"),
	}
	// The fake's own order is whatever Go's map iteration gave, so build the
	// first one from a fixed slice too and only compare the collector output.
	one.order = []string{"eth1", "eth0"}
	if !reflect.DeepEqual(collectFrom(one).Addresses, collectFrom(two).Addresses) {
		t.Fatalf("order is not deterministic:\n%+v\n%+v",
			collectFrom(one).Addresses, collectFrom(two).Addresses)
	}
}

func TestAnInterfaceNameIsSanitizedLikeAnyHostText(t *testing.T) {
	// An interface name is chosen on the host and the document is printed on
	// an operator's terminal in stdout mode (RECORD.md 4.14).
	f := host(t, map[string][]string{"ev\x1bil0": {"185.199.108.153/24"}})
	sec := collectFrom(f)
	if len(sec.Addresses) != 1 || sec.Addresses[0].Interface != "ev?il0" {
		t.Fatalf("interface name not sanitized: %+v", sec.Addresses)
	}
	d := hostdoc.New("h", 1)
	d.InterfaceAddresses = sec
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, b)
}

func TestAnAddressShapeTheKernelShouldNeverGiveIsSkipped(t *testing.T) {
	// Defensive: a nil address, an address of the wrong length, and an Addr
	// that is not an IPNet at all. None of these should occur, and none of
	// them may panic or reach the document.
	f := fakeHost{
		order:     []string{"eth0"},
		addresses: map[string][]net.Addr{},
		addrErr:   map[string]error{},
	}
	f.addresses["eth0"] = []net.Addr{
		&net.IPNet{IP: nil},
		&net.IPNet{IP: net.IP{1, 2, 3}},
		&net.TCPAddr{IP: net.ParseIP("185.199.109.153"), Port: 443},
		cidr(t, "185.199.108.153/24"),
	}
	sec := collectFrom(f)
	if !reflect.DeepEqual(addressStrings(sec), []string{"185.199.108.153"}) {
		t.Fatalf("addresses = %v, want only the well formed one", addressStrings(sec))
	}
}

func TestAnIPAddrIsAcceptedAsWellAsAnIPNet(t *testing.T) {
	// Linux returns *net.IPNet, but Addr is an interface and the collector
	// must not lose an address because the concrete type differed.
	f := fakeHost{
		order:     []string{"eth0"},
		addresses: map[string][]net.Addr{},
		addrErr:   map[string]error{},
	}
	f.addresses["eth0"] = []net.Addr{&net.IPAddr{IP: net.ParseIP("185.199.108.153")}}
	if got := addressStrings(collectFrom(f)); !reflect.DeepEqual(got, []string{"185.199.108.153"}) {
		t.Fatalf("addresses = %v, want the address from an *net.IPAddr", got)
	}
}

func TestAV4MappedAddressIsReportedAsV4(t *testing.T) {
	// The kernel does not assign these to interfaces. If one ever appears,
	// the address text and the family still have to agree, because the
	// control plane checks that they do.
	f := fakeHost{
		order:     []string{"eth0"},
		addresses: map[string][]net.Addr{},
		addrErr:   map[string]error{},
	}
	f.addresses["eth0"] = []net.Addr{
		&net.IPAddr{IP: net.ParseIP("::ffff:185.199.108.153")},
	}
	sec := collectFrom(f)
	if len(sec.Addresses) != 1 {
		t.Fatalf("addresses = %+v, want one", sec.Addresses)
	}
	if sec.Addresses[0].Family != "v4" || sec.Addresses[0].Address != "185.199.108.153" {
		t.Fatalf("v4-mapped entry = %+v, want a plain v4 address and family v4",
			sec.Addresses[0])
	}
}

func TestEveryEntryMarshalsAndItsFamilyAgreesWithItsAddress(t *testing.T) {
	f := host(t, map[string][]string{
		"eth0": {"185.199.108.153/24", "2606:50c0:8000::153/64", "10.0.0.5/8"},
	})
	sec := collectFrom(f)
	for _, a := range sec.Addresses {
		ip := net.ParseIP(a.Address)
		if ip == nil {
			t.Fatalf("address %q does not parse", a.Address)
		}
		wantFamily := "v6"
		if ip.To4() != nil {
			wantFamily = "v4"
		}
		if a.Family != wantFamily {
			t.Fatalf("%+v: family disagrees with the address", a)
		}
	}
	d := hostdoc.New("h", 1)
	d.InterfaceAddresses = sec
	if _, err := hostdoc.Marshal(d); err != nil {
		t.Fatalf("the section must marshal: %v", err)
	}
}

// TestTheRealHostReadDoesNotFail is the one test that touches the machine it
// runs on. It asserts nothing about what it finds, because that differs per
// machine, only that the exported entry point returns a section rather than
// panicking and that the section marshals.
func TestTheRealHostReadReturnsAMarshallableSection(t *testing.T) {
	sec := CollectInterfaceAddresses()
	if sec == nil {
		t.Fatal("the collector must never return nil")
	}
	d := hostdoc.New("h", 1)
	d.InterfaceAddresses = sec
	if _, err := hostdoc.Marshal(d); err != nil {
		t.Fatalf("the live section must marshal: %v", err)
	}
}
