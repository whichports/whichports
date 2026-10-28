package hostdoc

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
)

// New returns an empty document stamped with the current schema version and the
// given host identity. The timestamp is passed in, never read from the clock
// here, so callers stay in control of that side effect and tests stay
// deterministic.
func New(hostname string, collectedAtUnix int64) *Document {
	return &Document{
		SchemaVersion:   SchemaVersion,
		Hostname:        hostname,
		CollectedAtUnix: collectedAtUnix,
	}
}

// Marshal renders the document to indented JSON, the form printed by stdout
// mode and sent by the reporting mode. It fails closed: if any section carries
// a status or cause outside the defined enums, it returns an error rather than
// emit an unknown typed value onto the wire (SI-8). This is the last line of
// defence behind the type system, and the tests exercise it directly.
func Marshal(d *Document) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("hostdoc: nil document")
	}
	if d.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("hostdoc: unexpected schema_version %d, want %d",
			d.SchemaVersion, SchemaVersion)
	}
	if err := validate(d); err != nil {
		return nil, err
	}
	return json.MarshalIndent(d, "", "  ")
}

// validate walks every section and checks its typed fields are defined values.
// It exists so a programming mistake surfaces as a marshalling error in a test
// rather than as an undefined string reaching the control plane.
func validate(d *Document) error {
	if d.Sockets != nil {
		if err := checkSection("sockets", d.Sockets.Section); err != nil {
			return err
		}
		if err := checkSources("sockets", d.Sockets.Sources, SocketSources); err != nil {
			return err
		}
		for i, s := range d.Sockets.Listening {
			if s.Protocol != "tcp" && s.Protocol != "udp" {
				return fmt.Errorf("hostdoc: sockets[%d] protocol %q not tcp or udp", i, s.Protocol)
			}
			if s.Family != "v4" && s.Family != "v6" {
				return fmt.Errorf("hostdoc: sockets[%d] family %q not v4 or v6", i, s.Family)
			}
			// A uid is a 32-bit unsigned value on Linux, so anything outside
			// that range was never read out of /proc and must not ship.
			if s.OwnerUID != nil && (*s.OwnerUID < 0 || *s.OwnerUID > math.MaxUint32) {
				return fmt.Errorf("hostdoc: sockets[%d] owner_uid %d out of uid range", i, *s.OwnerUID)
			}
			// The name is a lookup of the uid, so a name with no uid is a
			// value nothing measured, and a name past the cap is not a login
			// name (MaxOwnerNameLen, hostdoc.go).
			if s.OwnerName != "" && s.OwnerUID == nil {
				return fmt.Errorf("hostdoc: sockets[%d] has owner_name %q without an owner_uid", i, s.OwnerName)
			}
			if len(s.OwnerName) > MaxOwnerNameLen {
				return fmt.Errorf("hostdoc: sockets[%d] owner_name is %d bytes, the cap is %d", i, len(s.OwnerName), MaxOwnerNameLen)
			}
			// The cgroup path is a path the kernel handed out, so it is
			// absolute and bounded, and the unit is its last element or
			// nothing. A unit with no path, or one the path does not end
			// in, is a value nothing measured.
			if len(s.Cgroup) > MaxCgroupPathLen {
				return fmt.Errorf("hostdoc: sockets[%d] cgroup is %d bytes, the cap is %d", i, len(s.Cgroup), MaxCgroupPathLen)
			}
			if s.Cgroup != "" && s.Cgroup[0] != '/' {
				return fmt.Errorf("hostdoc: sockets[%d] cgroup %q is not an absolute path", i, s.Cgroup)
			}
			if s.Unit != "" {
				if s.Cgroup == "" {
					return fmt.Errorf("hostdoc: sockets[%d] has unit %q without a cgroup", i, s.Unit)
				}
				if s.Cgroup != "/"+s.Unit && !strings.HasSuffix(s.Cgroup, "/"+s.Unit) {
					return fmt.Errorf("hostdoc: sockets[%d] unit %q is not the last element of cgroup %q", i, s.Unit, s.Cgroup)
				}
			}
		}
	}
	if d.SocketUnits != nil {
		if err := checkSocketUnits(d.SocketUnits); err != nil {
			return err
		}
	}
	if d.Packages != nil {
		if err := checkPackages(d.Packages); err != nil {
			return err
		}
	}
	if d.InterfaceAddresses != nil {
		if err := checkSection("interface_addresses", d.InterfaceAddresses.Section); err != nil {
			return err
		}
		for i, a := range d.InterfaceAddresses.Addresses {
			if a.Family != "v4" && a.Family != "v6" {
				return fmt.Errorf("hostdoc: interface_addresses[%d] family %q not v4 or v6", i, a.Family)
			}
			if a.Address == "" {
				return fmt.Errorf("hostdoc: interface_addresses[%d] has an empty address", i)
			}
			if a.Interface == "" {
				return fmt.Errorf("hostdoc: interface_addresses[%d] has an empty interface name", i)
			}
		}
	}
	if d.Nftables != nil {
		if err := checkSection("nftables", d.Nftables.Section); err != nil {
			return err
		}
		for i, tb := range d.Nftables.Tables {
			if !inList(tb.Family, NftFamilies) {
				return fmt.Errorf("hostdoc: nftables table %d family %q is not a defined family", i, tb.Family)
			}
			for j, ch := range tb.Chains {
				if ch.Hook != "" && !inList(ch.Hook, NftHooks) {
					return fmt.Errorf("hostdoc: nftables %s/%s chain %d hook %q is not a defined hook", tb.Family, tb.Name, j, ch.Hook)
				}
				if ch.Policy != "" && ch.Policy != "accept" && ch.Policy != "drop" {
					return fmt.Errorf("hostdoc: nftables chain %s policy %q not accept or drop", ch.Name, ch.Policy)
				}
				for k, r := range ch.Rules {
					if r.Rendered != "full" && r.Rendered != "partial" && r.Rendered != "none" {
						return fmt.Errorf("hostdoc: nftables chain %s rule %d rendered %q not full, partial or none", ch.Name, k, r.Rendered)
					}
				}
			}
		}
	}
	if d.Ufw != nil {
		if err := checkSection("ufw", d.Ufw.Section); err != nil {
			return err
		}
		if err := checkSources("ufw", d.Ufw.Sources, UfwSources); err != nil {
			return err
		}
	}
	if d.Firewalld != nil {
		if err := checkSection("firewalld", d.Firewalld.Section); err != nil {
			return err
		}
		if err := checkSources("firewalld", d.Firewalld.Sources, FirewalldSources); err != nil {
			return err
		}
		for i, z := range d.Firewalld.Zones {
			if z.Origin != "etc" && z.Origin != "vendor" {
				return fmt.Errorf("hostdoc: firewalld zone %d origin %q not etc or vendor", i, z.Origin)
			}
		}
	}
	if d.RuleFiles != nil {
		if err := checkSection("rule_files", d.RuleFiles.Section); err != nil {
			return err
		}
		for i, f := range d.RuleFiles.Files {
			if f.Path == "" {
				return fmt.Errorf("hostdoc: rule_files[%d] has an empty path", i)
			}
		}
	}
	if d.Containers != nil {
		if err := checkSection("containers", d.Containers.Section); err != nil {
			return err
		}
		if err := checkSources("containers", d.Containers.Sources, ContainerSources); err != nil {
			return err
		}
		for _, list := range [][]Container{d.Containers.Docker, d.Containers.Podman} {
			for i, c := range list {
				if c.ID == "" {
					return fmt.Errorf("hostdoc: containers[%d] has an empty id", i)
				}
				for j, p := range c.Ports {
					if p.HostPort <= 0 || p.HostPort > 65535 || p.ContainerPort < 0 || p.ContainerPort > 65535 {
						return fmt.Errorf("hostdoc: container %s port %d out of range: %+v", c.ID, j, p)
					}
				}
			}
		}
	}
	if d.Overlays != nil {
		if err := checkSection("overlays", d.Overlays.Section); err != nil {
			return err
		}
		if err := checkSources("overlays", d.Overlays.Sources, OverlaySources); err != nil {
			return err
		}
		for i, oi := range d.Overlays.Interfaces {
			if oi.Name == "" {
				return fmt.Errorf("hostdoc: overlays interface %d has an empty name", i)
			}
		}
	}
	for name, s := range map[string]*IptablesSection{"iptables": d.Iptables, "ip6tables": d.Ip6tables} {
		if s == nil {
			continue
		}
		if err := checkSection(name, s.Section); err != nil {
			return err
		}
		if err := checkSources(name, s.Sources, IptTables); err != nil {
			return err
		}
		for _, tb := range s.Tables {
			for _, ch := range tb.Chains {
				if ch.Policy != "" && ch.Policy != "accept" && ch.Policy != "drop" {
					return fmt.Errorf("hostdoc: %s chain %s policy %q not accept or drop", name, ch.Name, ch.Policy)
				}
				for k, r := range ch.Rules {
					if r.Rendered != "full" && r.Rendered != "partial" && r.Rendered != "none" {
						return fmt.Errorf("hostdoc: %s chain %s rule %d rendered %q invalid", name, ch.Name, k, r.Rendered)
					}
				}
			}
		}
	}
	return nil
}

// checkSocketUnits validates the socket-unit section. Most of it is the same
// enum checking every other section gets, and the rest is the honesty rule of
// this section written as a gate: a bare port specifies no address, so an
// entry that fills in an address, a family or a true AddressSpecified for one
// is a bug, and the document does not leave the host carrying it. A wrong
// address on a port is exactly the kind of inference-presented-as-measurement
// PRODUCT.md 4b forbids, and this is where it fails closed.
func checkSocketUnits(s *SocketUnitsSection) error {
	if err := checkSection("socket_units", s.Section); err != nil {
		return err
	}
	if err := checkSources("socket_units", s.Sources, SocketUnitSources); err != nil {
		return err
	}
	for i, u := range s.Units {
		if u.Name == "" {
			return fmt.Errorf("hostdoc: socket_units[%d] has an empty name", i)
		}
		if u.File == "" {
			return fmt.Errorf("hostdoc: socket_units[%d] (%s) has an empty file path", i, u.Name)
		}
		if !inList(u.Origin, SocketUnitOrigins) {
			return fmt.Errorf("hostdoc: socket_units[%d] (%s) origin %q is not a defined origin", i, u.Name, u.Origin)
		}
		if u.ServiceSource != "" && !inList(u.ServiceSource, SocketUnitServiceSources) {
			return fmt.Errorf("hostdoc: socket_units[%d] (%s) service_source %q is not defined", i, u.Name, u.ServiceSource)
		}
		// A service unit name without a source would leave a reader unable to
		// tell a stated fact from an applied rule, which is the distinction
		// this section exists to keep.
		if u.ServiceUnit != "" && u.ServiceSource == "" {
			return fmt.Errorf("hostdoc: socket_units[%d] (%s) names a service unit with no service_source", i, u.Name)
		}
		for _, reason := range u.Incomplete {
			if !inList(reason, SocketUnitIncompleteReasons) {
				return fmt.Errorf("hostdoc: socket_units[%d] (%s) incomplete reason %q is not defined", i, u.Name, reason)
			}
		}
		for j, l := range u.Listen {
			if err := checkSocketUnitListen(u.Name, j, l); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkSocketUnitListen(unit string, j int, l SocketUnitListen) error {
	if !slices.Contains(SocketUnitListenDirectives, l.Directive) {
		return fmt.Errorf("hostdoc: %s listen[%d] directive %q is not one of %v", unit, j, l.Directive, SocketUnitListenDirectives)
	}
	if !inList(l.Kind, SocketUnitKinds) {
		return fmt.Errorf("hostdoc: %s listen[%d] kind %q is not a defined kind", unit, j, l.Kind)
	}
	if l.AddressFamily != "" && l.AddressFamily != "v4" && l.AddressFamily != "v6" {
		return fmt.Errorf("hostdoc: %s listen[%d] address_family %q not v4, v6 or empty", unit, j, l.AddressFamily)
	}
	// The bare-port rule. systemd.socket(5) leaves the address and the family
	// of "ListenStream=9090" to BindIPv6Only= and a sysctl, neither of which
	// this collector reads, so claiming either here would be an invention.
	if l.Kind == "port_only" {
		if l.AddressSpecified || l.Address != "" || l.AddressFamily != "" {
			return fmt.Errorf("hostdoc: %s listen[%d] is a bare port and claims an address (%q/%q/%v)",
				unit, j, l.Address, l.AddressFamily, l.AddressSpecified)
		}
	}
	if l.AddressSpecified != (l.Address != "") {
		return fmt.Errorf("hostdoc: %s listen[%d] address_specified %v disagrees with address %q",
			unit, j, l.AddressSpecified, l.Address)
	}
	if l.Kind == "ipv4" && l.AddressFamily != "v4" {
		return fmt.Errorf("hostdoc: %s listen[%d] is ipv4 with family %q", unit, j, l.AddressFamily)
	}
	if l.Kind == "ipv6" && l.AddressFamily != "v6" {
		return fmt.Errorf("hostdoc: %s listen[%d] is ipv6 with family %q", unit, j, l.AddressFamily)
	}
	// Only the three IP forms carry a TCP or UDP port, and a port that is
	// carried is a real one. Everything else, a unix path included, is 0.
	switch l.Kind {
	case "port_only", "ipv4", "ipv6":
		if l.Port < 1 || l.Port > 65535 {
			return fmt.Errorf("hostdoc: %s listen[%d] port %d out of range", unit, j, l.Port)
		}
	default:
		if l.Port != 0 {
			return fmt.Errorf("hostdoc: %s listen[%d] kind %q carries port %d", unit, j, l.Kind, l.Port)
		}
	}
	return nil
}

// checkSources validates a per-source verdict map: only the allowed keys, and
// every verdict a valid section.
func checkSources(name string, sources map[string]Section, allowed []string) error {
	for key, src := range sources {
		if !inList(key, allowed) {
			return fmt.Errorf("hostdoc: %s source %q is not a known source", name, key)
		}
		if err := checkSection(name+"/"+key, src); err != nil {
			return err
		}
	}
	return nil
}

// inList reports whether v is one of the allowed values.
func inList(v string, allowed []string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func checkSection(name string, s Section) error {
	if !s.Status.valid() {
		return fmt.Errorf("hostdoc: section %s has invalid status %q", name, s.Status)
	}
	if !s.Cause.valid() {
		return fmt.Errorf("hostdoc: section %s has invalid cause %q", name, s.Cause)
	}
	// A collected section carries no cause; a failed one must carry one. This
	// keeps the two fields honest with each other.
	if s.Status == StatusCollected && s.Cause != CauseNone {
		return fmt.Errorf("hostdoc: section %s collected but has cause %q", name, s.Cause)
	}
	return nil
}
