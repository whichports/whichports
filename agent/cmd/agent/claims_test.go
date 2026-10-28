package main

import (
	"net/netip"
	"reflect"
	"testing"
)

func document(addresses ...string) []byte {
	body := `{"schema_version":1,"interface_addresses":{"addresses":[`
	for i, a := range addresses {
		if i > 0 {
			body += ","
		}
		body += `{"interface":"eth0","family":"v4","address":"` + a + `","global":true}`
	}
	return []byte(body + `]}}`)
}

// Only public addresses leave, whatever the document's own global bit says,
// because nothing may decide from that bit (hostdoc.InterfaceAddress).
func TestClaimedAddressesAreThePublicOnesOnly(t *testing.T) {
	got := claimedAddresses(document(
		"2606:50c0:8000::153", "185.199.108.153", "10.0.0.5", "192.168.1.2",
		"172.16.0.1", "fd00::1", "127.0.0.1", "::1", "fe80::1", "169.254.1.1",
		"::ffff:185.199.108.154", "fe80::1%eth0", "not an address", "",
		"185.199.108.153", "224.0.0.1", "0.0.0.0", "::"))
	want := []netip.Addr{netip.MustParseAddr("185.199.108.153"),
		netip.MustParseAddr("2606:50c0:8000::153")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("claimed = %v, want %v", got, want)
	}
}

func TestADocumentWithoutTheSectionClaimsNothing(t *testing.T) {
	for _, doc := range [][]byte{
		[]byte(`{"schema_version":1}`), []byte(`not json`), nil,
		[]byte(`{"interface_addresses":{"addresses":"x"}}`),
		[]byte(`{"interface_addresses":null}`),
	} {
		if got := claimedAddresses(doc); len(got) != 0 {
			t.Errorf("claimed %v from %q", got, doc)
		}
	}
}
