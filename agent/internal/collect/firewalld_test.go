package collect

// The firewalld collector's review. The alma-firewalld fixture is modelled on
// /etc/firewalld captured from the AlmaLinux 10.2 box on 2026-08-12: the conf
// keys are verbatim (including StrictForwardPorts, the setting PRODUCT.md 4d
// turns on), the zone shapes are the captured ones with the box's service set
// rewritten, the vendor files are constructed simplified examples, and the
// stray .xml.old backup next to the live zones was really there.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

func TestFirewalldAlmaProfile(t *testing.T) {
	sec := CollectFirewalld("testdata/fsroots/alma-firewalld")
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	for _, src := range hostdoc.FirewalldSources {
		if sec.Sources[src].Status != hostdoc.StatusCollected {
			t.Fatalf("source %s = %+v, want collected", src, sec.Sources[src])
		}
	}
	if sec.Conf["DefaultZone"] != "public" || sec.Conf["FirewallBackend"] != "nftables" {
		t.Fatalf("conf wrong: %v", sec.Conf)
	}
	// The Podman auto-open story hinges on this key (PRODUCT.md 4d), so its
	// presence in the document is load-bearing.
	if sec.Conf["StrictForwardPorts"] != "no" {
		t.Fatalf("StrictForwardPorts = %q, want no", sec.Conf["StrictForwardPorts"])
	}

	// Zones: admin files first then vendor, each sorted by file name, and the
	// .xml.old backup must not appear.
	wantOrder := []struct{ origin, file string }{
		{"etc", "public.xml"}, {"etc", "wg.xml"},
		{"vendor", "home.xml"}, {"vendor", "public.xml"},
	}
	if len(sec.Zones) != len(wantOrder) {
		t.Fatalf("zone count = %d (%+v), want %d", len(sec.Zones), sec.Zones, len(wantOrder))
	}
	for i, w := range wantOrder {
		if sec.Zones[i].Origin != w.origin || sec.Zones[i].File != w.file {
			t.Fatalf("zones[%d] = %s/%s, want %s/%s", i, sec.Zones[i].Origin, sec.Zones[i].File, w.origin, w.file)
		}
	}

	pub := sec.Zones[0]
	if !pub.Parsed || pub.Name != "public" {
		t.Fatalf("public zone not parsed: %+v", pub)
	}
	assertStrings(t, "public services", pub.Services, []string{"ssh", "dhcpv6-client", "cockpit"})
	if len(pub.Ports) != 1 || pub.Ports[0] != (hostdoc.FirewalldPort{Port: "8080", Protocol: "tcp"}) {
		t.Fatalf("public ports wrong: %+v", pub.Ports)
	}
	if !pub.Forward || pub.Masquerade {
		t.Fatalf("public forward/masquerade wrong: %+v", pub)
	}

	wg := sec.Zones[1]
	if wg.Target != "ACCEPT" || len(wg.Interfaces) != 1 || wg.Interfaces[0] != "wg0" {
		t.Fatalf("wg zone wrong: %+v", wg)
	}

	home := sec.Zones[2]
	if !home.Masquerade || len(home.SourceAddrs) != 1 || home.SourceAddrs[0] != "192.0.2.0/24" {
		t.Fatalf("home zone wrong: %+v", home)
	}
	if len(home.ForwardPorts) != 1 || home.ForwardPorts[0] != (hostdoc.FirewalldForward{
		Port: "8443", Protocol: "tcp", ToPort: "443", ToAddr: "192.0.2.9",
	}) {
		t.Fatalf("home forward-port wrong: %+v", home.ForwardPorts)
	}
}

func TestFirewalldAbsentIsNotPresent(t *testing.T) {
	sec := CollectFirewalld("testdata/fsroots/ubuntu-ufw")
	if sec.Status != hostdoc.StatusNotPresent {
		t.Fatalf("status = %q, want not_present", sec.Status)
	}
}

func TestFirewalldHostileZones(t *testing.T) {
	sec := CollectFirewalld("testdata/fsroots/hostile")
	// A conf file holding only comments is a healthy read of an empty
	// configuration, not an error.
	if got := sec.Sources["firewalld.conf"]; got.Status != hostdoc.StatusCollected {
		t.Fatalf("comment-only conf = %+v, want collected", got)
	}
	if len(sec.Conf) != 0 {
		t.Fatalf("comment-only conf produced keys: %v", sec.Conf)
	}
	// Both broken zone files are reported, unparsed, with their names: a
	// broken zone file on a firewall host is a finding, not a skip.
	if len(sec.Zones) != 2 {
		t.Fatalf("zone count = %d, want 2 (%+v)", len(sec.Zones), sec.Zones)
	}
	for _, z := range sec.Zones {
		if z.Parsed {
			t.Fatalf("hostile zone %s claims parsed", z.File)
		}
		if len(z.Services) != 0 {
			t.Fatalf("unparsed zone %s carries content: %+v", z.File, z)
		}
	}

	d := hostdoc.New("h", 1)
	d.Firewalld = sec
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, b)
}

func TestFirewalldDeterministic(t *testing.T) {
	d1 := hostdoc.New("h", 1)
	d1.Firewalld = CollectFirewalld("testdata/fsroots/alma-firewalld")
	d2 := hostdoc.New("h", 1)
	d2.Firewalld = CollectFirewalld("testdata/fsroots/alma-firewalld")
	b1, err1 := hostdoc.Marshal(d1)
	b2, err2 := hostdoc.Marshal(d2)
	if err1 != nil || err2 != nil {
		t.Fatalf("marshal errors: %v %v", err1, err2)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("two collections of the same firewalld state differ")
	}
}

func TestFirewalldUnreadableZoneIsNotSilentlyUnparsed(t *testing.T) {
	// A zone file we are not allowed to open arrived with Parsed false, which
	// is the same signal a malformed file gets. The section then said
	// collected, so nothing on the screen could tell "this zone is broken"
	// from "we were not allowed to look", and a host whose firewall could not
	// be read looked like a host whose firewall says nothing.
	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores the mode this test relies on")
	}
	root := t.TempDir()
	zones := filepath.Join(root, "etc/firewalld/zones")
	if err := os.MkdirAll(zones, 0o755); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(zones, "public.xml")
	if err := os.WriteFile(locked, []byte("<zone/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })

	sec := CollectFirewalld(root)
	if got := sec.Sources["etc_zones"]; got.Status != hostdoc.StatusPermissionDenied {
		t.Fatalf("etc_zones = %q, want permission_denied", got.Status)
	}
	// The zone is still listed, because a zone file being there is itself
	// evidence. What changed is that its source now says why it is unparsed.
	if len(sec.Zones) != 1 || sec.Zones[0].Parsed {
		t.Fatalf("zones = %+v, want the file listed and unparsed", sec.Zones)
	}
}
