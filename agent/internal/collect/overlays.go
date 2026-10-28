// This file is the overlays collector: which network interfaces exist and
// what kind they are, plus whether an overlay daemon is present. The overlay
// networks' firewall chains already arrive verbatim in the kernel sections;
// what the control plane still needs is the identity evidence to name the
// layer: this interface is a WireGuard device, this one is a tun device, a
// tailscaled is running here. WireGuard itself adds no netfilter chains
// (docs/RECORD.md section 5), which is exactly why interface identity is the
// only trace of it.
package collect

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// Identity sources, each verified 2026-08-13:
//   - /sys/class/net/<if>/type is the ARPHRD number (1 ether, 772 loopback,
//     65534 none, observed live).
//   - /sys/class/net/<if>/uevent carries DEVTYPE for drivers that set one:
//     "wireguard" (drivers/net/wireguard/device.c at v6.8 sets it from
//     KBUILD_MODNAME), "bridge" observed live.
//   - /sys/class/net/<if>/tun_flags exists only on tun devices (present on a
//     live tailscale0, absent on ethernet).
//   - tailscaled's socket and state directory, both observed live.
//   - netbird's daemon socket, its documented default (docs.netbird.io).
const (
	tailscaleSocket   = "run/tailscale/tailscaled.sock"
	tailscaleStateDir = "var/lib/tailscale"
	netbirdSocket     = "var/run/netbird.sock"
)

// CollectOverlays reads interface identities from sysfs under root and
// checks for the overlay daemons' presence.
func CollectOverlays(root string) *hostdoc.OverlaysSection {
	sec := &hostdoc.OverlaysSection{Sources: map[string]hostdoc.Section{}}

	ifaces, v := readInterfaces(filepath.Join(root, "sys/class/net"))
	sec.Sources["interfaces"] = v
	sec.Interfaces = ifaces

	ts := hostdoc.OverlayPresence{}
	ts.Socket, v = pathPresence(filepath.Join(root, tailscaleSocket))
	// The state directory's verdict used to be discarded, so a permission
	// error on it came back as StateDir false and the source still read
	// collected: "Tailscale is not here" when the truth was "I was not
	// allowed to look". Both reads answer for the same source, so the worse
	// of the two is the one that has to survive.
	var stateVerdict hostdoc.Section
	ts.StateDir, stateVerdict = pathPresence(filepath.Join(root, tailscaleStateDir))
	sec.Sources["tailscale"] = worseVerdict(v, stateVerdict)
	sec.Tailscale = &ts

	nb := hostdoc.OverlayPresence{}
	nb.Socket, v = pathPresence(filepath.Join(root, netbirdSocket))
	sec.Sources["netbird"] = v
	sec.Netbird = &nb

	sec.Section = aggregateSources(sec.Sources)
	return sec
}

// pathPresence reports whether a path exists. Absence is a measurement, so
// the verdict stays collected for both answers; only a permission error on
// the stat makes the answer untrustworthy.
func pathPresence(path string) (bool, hostdoc.Section) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, hostdoc.Section{Status: hostdoc.StatusCollected}
	case os.IsNotExist(err):
		return false, hostdoc.Section{Status: hostdoc.StatusCollected}
	case os.IsPermission(err):
		return false, hostdoc.Section{Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission}
	default:
		return false, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	}
}

// readInterfaces lists every interface with its identity evidence.
func readInterfaces(netDir string) ([]hostdoc.OverlayInterface, hostdoc.Section) {
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return nil, fileVerdict(err)
	}
	var out []hostdoc.OverlayInterface
	// pathPresence above already draws the line this loop has to draw too:
	// absence is a measurement, a permission error is not. Listing the
	// directory succeeding says nothing about the files inside it, and a
	// denied read here leaves Type and DevType empty, which is exactly what
	// an interface with no identity evidence looks like. That matters more
	// than it sounds: the empty answer is how a WireGuard interface is told
	// apart from a Tailscale one (RECORD.md 4.23), so a silent denial can
	// change what the overlay looks like rather than only hiding a field.
	denied := false
	for _, e := range entries {
		name := e.Name()
		dir := filepath.Join(netDir, name)
		oi := hostdoc.OverlayInterface{Name: sanitizeName(name)}

		b, err := os.ReadFile(filepath.Join(dir, "type"))
		switch {
		case err == nil:
			oi.Type = sanitizeName(strings.TrimSpace(string(b)))
		case os.IsPermission(err):
			denied = true
		}
		b, err = os.ReadFile(filepath.Join(dir, "uevent"))
		switch {
		case err == nil:
			for _, line := range strings.Split(string(b), "\n") {
				if v, ok := strings.CutPrefix(line, "DEVTYPE="); ok {
					oi.DevType = sanitizeName(strings.TrimSpace(v))
					break
				}
			}
		case os.IsPermission(err):
			denied = true
		}
		if _, err := os.Stat(filepath.Join(dir, "tun_flags")); err == nil {
			oi.Tun = true
		} else if os.IsPermission(err) {
			denied = true
		}
		out = append(out, oi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if denied {
		// The interfaces are still reported. What changes is that the source
		// no longer claims their identity evidence is complete.
		return out, hostdoc.Section{Status: hostdoc.StatusPermissionDenied,
			Cause: hostdoc.CausePermission}
	}
	return out, hostdoc.Section{Status: hostdoc.StatusCollected}
}
