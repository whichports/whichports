package collect

// The overlays collector's review. Runtime fixture trees because sysfs
// cannot be committed: uevent content, the tun_flags marker and the daemon
// paths are all plain files here, which is exactly how the collector reads
// them.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// writeIface builds one /sys/class/net entry.
func writeIface(t *testing.T, root, name, typ, uevent string, tun bool) {
	t.Helper()
	dir := filepath.Join(root, "sys/class/net", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if typ != "" {
		if err := os.WriteFile(filepath.Join(dir, "type"), []byte(typ+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if uevent != "" {
		if err := os.WriteFile(filepath.Join(dir, "uevent"), []byte(uevent), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if tun {
		if err := os.WriteFile(filepath.Join(dir, "tun_flags"), []byte("0x5001\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOverlaysInterfaceIdentity(t *testing.T) {
	root := t.TempDir()
	writeIface(t, root, "eth0", "1", "INTERFACE=eth0\nIFINDEX=2\n", false)
	writeIface(t, root, "wg0", "65534", "DEVTYPE=wireguard\nINTERFACE=wg0\nIFINDEX=5\n", false)
	writeIface(t, root, "tailscale0", "65534", "INTERFACE=tailscale0\nIFINDEX=7\n", true)
	writeIface(t, root, "br0", "1", "DEVTYPE=bridge\nINTERFACE=br0\n", false)

	sec := CollectOverlays(root)
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
	want := []hostdoc.OverlayInterface{
		{Name: "br0", Type: "1", DevType: "bridge"},
		{Name: "eth0", Type: "1"},
		{Name: "tailscale0", Type: "65534", Tun: true},
		{Name: "wg0", Type: "65534", DevType: "wireguard"},
	}
	if len(sec.Interfaces) != len(want) {
		t.Fatalf("interfaces = %+v, want %+v", sec.Interfaces, want)
	}
	for i := range want {
		if sec.Interfaces[i] != want[i] {
			t.Errorf("interfaces[%d] = %+v, want %+v", i, sec.Interfaces[i], want[i])
		}
	}
	// No daemons in this root: measured false, sources still collected.
	if sec.Tailscale.Socket || sec.Tailscale.StateDir || sec.Netbird.Socket {
		t.Fatalf("daemon presence should be false: %+v %+v", sec.Tailscale, sec.Netbird)
	}
	if sec.Sources["tailscale"].Status != hostdoc.StatusCollected {
		t.Fatalf("tailscale source = %+v, want collected", sec.Sources["tailscale"])
	}
}

func TestOverlaysDaemonPresence(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"run/tailscale/tailscaled.sock", "var/lib/tailscale/x", "var/run/netbird.sock"} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sec := CollectOverlays(root)
	if !sec.Tailscale.Socket || !sec.Tailscale.StateDir || !sec.Netbird.Socket {
		t.Fatalf("daemon presence should be true: %+v %+v", sec.Tailscale, sec.Netbird)
	}
	// No sysfs in this root: the interfaces source says so, and one healthy
	// source keeps the section collected.
	if sec.Sources["interfaces"].Status != hostdoc.StatusNotPresent {
		t.Fatalf("interfaces source = %+v, want not_present", sec.Sources["interfaces"])
	}
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("status = %q, want collected", sec.Status)
	}
}

func TestOverlaysHostileDevTypeSanitized(t *testing.T) {
	root := t.TempDir()
	writeIface(t, root, "weird0", "1", "DEVTYPE=ev\x1bil\nINTERFACE=weird0\n", false)
	sec := CollectOverlays(root)
	if len(sec.Interfaces) != 1 || sec.Interfaces[0].DevType != "ev?il" {
		t.Fatalf("devtype not sanitized: %+v", sec.Interfaces)
	}
	d := hostdoc.New("h", 1)
	d.Overlays = sec
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, b)
}

func TestOverlaysDeterministic(t *testing.T) {
	root := t.TempDir()
	writeIface(t, root, "b0", "1", "", false)
	writeIface(t, root, "a0", "1", "", false)
	d1 := hostdoc.New("h", 1)
	d1.Overlays = CollectOverlays(root)
	d2 := hostdoc.New("h", 1)
	d2.Overlays = CollectOverlays(root)
	b1, err1 := hostdoc.Marshal(d1)
	b2, err2 := hostdoc.Marshal(d2)
	if err1 != nil || err2 != nil {
		t.Fatalf("marshal errors: %v %v", err1, err2)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("two collections of the same interfaces differ")
	}
	if d1.Overlays.Interfaces[0].Name != "a0" {
		t.Fatalf("interfaces not sorted: %+v", d1.Overlays.Interfaces)
	}
}

func TestOverlaysUnreadableIdentityIsNotAnInterfaceWithoutOne(t *testing.T) {
	// The bug this pins. Listing /sys/class/net succeeding says nothing about
	// the files inside each interface directory, and a denied read of type or
	// uevent left Type and DevType empty, which is exactly what an interface
	// carrying no identity evidence looks like.
	//
	// That is worse than a missing field. An empty DevType is how a
	// WireGuard interface is told apart from a Tailscale one (RECORD.md
	// 4.23), so a silent denial does not hide the answer, it changes it.
	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores the mode this test relies on")
	}
	root := t.TempDir()
	writeIface(t, root, "eth0", "1", "INTERFACE=eth0\n", false)
	writeIface(t, root, "wg0", "65534", "DEVTYPE=wireguard\nINTERFACE=wg0\n", false)

	locked := filepath.Join(root, "sys/class/net/wg0/uevent")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })

	sec := CollectOverlays(root)
	if got := sec.Sources["interfaces"]; got.Status != hostdoc.StatusPermissionDenied {
		t.Fatalf("interfaces source = %q, want permission_denied", got.Status)
	}
	if got := sec.Sources["interfaces"]; got.Cause != hostdoc.CausePermission {
		t.Fatalf("interfaces cause = %q, want permission", got.Cause)
	}
	// Both interfaces are still reported. A denial narrows what we claim to
	// know, it does not empty the list.
	if len(sec.Interfaces) != 2 {
		t.Fatalf("interfaces = %+v, want both still listed", sec.Interfaces)
	}
}
