// This file is the firewalld collector: the permanent configuration, read
// from firewalld's own files, never over DBus and never by executing
// firewall-cmd. What firewalld has actually materialised in the kernel right
// now is the nftables section's job (FirewallBackend permitting); this
// section is the configured intent, and the control plane compares the two.
package collect

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// zoneFileLimit caps how much of a zone file is parsed. Real zone files are a
// few kilobytes; a runaway file must not swallow the agent's memory.
const zoneFileLimit = 1 << 20

// CollectFirewalld reads firewalld's configuration under root (normally
// "/"). Three sources, each with its own verdict: firewalld.conf, the admin
// zone directory /etc/firewalld/zones, and the vendor zone directory
// /usr/lib/firewalld/zones. firewalld resolves a same-named zone in /etc over
// the vendor file; both are reported with their origin, because resolving the
// override is a conclusion and conclusions belong to the control plane.
func CollectFirewalld(root string) *hostdoc.FirewalldSection {
	sec := &hostdoc.FirewalldSection{Sources: map[string]hostdoc.Section{}}

	conf, v := readKeyValueFile(filepath.Join(root, "etc/firewalld/firewalld.conf"))
	sec.Sources["firewalld.conf"] = v
	sec.Conf = conf

	etcZones, v := readZoneDir(filepath.Join(root, "etc/firewalld/zones"), "etc")
	sec.Sources["etc_zones"] = v
	vendorZones, v := readZoneDir(filepath.Join(root, "usr/lib/firewalld/zones"), "vendor")
	sec.Sources["vendor_zones"] = v

	sec.Zones = append(etcZones, vendorZones...)
	// Deterministic order: admin zones first, then vendor, each by file name.
	sort.Slice(sec.Zones, func(i, j int) bool {
		if sec.Zones[i].Origin != sec.Zones[j].Origin {
			return sec.Zones[i].Origin == "etc"
		}
		return sec.Zones[i].File < sec.Zones[j].File
	})

	sec.Section = aggregateSources(sec.Sources)
	return sec
}

// readZoneDir reads every *.xml file in one zone directory. Editors and
// firewalld itself leave *.xml.old backups next to the live files (observed
// on AlmaLinux 10, 2026-08-12); only exact .xml files are zones. A file that
// exists but does not parse is still reported, with Parsed false, because
// "there is a zone file here and it is broken" is a finding.
func readZoneDir(dir, origin string) ([]hostdoc.FirewalldZone, hostdoc.Section) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fileVerdict(err)
	}
	var zones []hostdoc.FirewalldZone
	// Listing the directory succeeding does not mean every file in it was
	// readable. A zone we could not open arrives here as Parsed false, which
	// is the same signal a malformed file gets, so without this the section
	// would say collected and a reader could not tell "this zone is broken"
	// from "we were not allowed to look". Reporting the source as denied is
	// how that reaches the screen, because aggregateSources carries it and
	// the dashboard prints the per-source verdict (RECORD.md 4.17).
	denied := false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".xml") {
			continue
		}
		z := hostdoc.FirewalldZone{
			File:   sanitizeName(name),
			Origin: origin,
			Name:   sanitizeName(strings.TrimSuffix(name, ".xml")),
		}
		content, err := os.ReadFile(filepath.Join(dir, name))
		switch {
		case err != nil:
			if os.IsPermission(err) {
				denied = true
			}
		case len(content) <= zoneFileLimit:
			if parsed, ok := parseZoneXML(content); ok {
				z = mergeZone(z, parsed)
				z.Parsed = true
			}
		}
		zones = append(zones, z)
	}
	if denied {
		return zones, hostdoc.Section{Status: hostdoc.StatusPermissionDenied,
			Cause: hostdoc.CausePermission}
	}
	return zones, hostdoc.Section{Status: hostdoc.StatusCollected}
}

// zoneXML mirrors the parts of firewalld's zone schema this agent reports.
// Unknown elements are ignored by encoding/xml, which is the right posture:
// report what is understood, never fail a zone for having a newer feature.
type zoneXML struct {
	XMLName  xml.Name `xml:"zone"`
	Target   string   `xml:"target,attr"`
	Services []struct {
		Name string `xml:"name,attr"`
	} `xml:"service"`
	Ports []struct {
		Port     string `xml:"port,attr"`
		Protocol string `xml:"protocol,attr"`
	} `xml:"port"`
	Interfaces []struct {
		Name string `xml:"name,attr"`
	} `xml:"interface"`
	Sources []struct {
		Address string `xml:"address,attr"`
	} `xml:"source"`
	Masquerade   *struct{} `xml:"masquerade"`
	Forward      *struct{} `xml:"forward"`
	ForwardPorts []struct {
		Port     string `xml:"port,attr"`
		Protocol string `xml:"protocol,attr"`
		ToPort   string `xml:"to-port,attr"`
		ToAddr   string `xml:"to-addr,attr"`
	} `xml:"forward-port"`
}

// parseZoneXML parses one zone file. Go's encoding/xml does not process
// custom DTD entities, so entity-expansion tricks fail the parse rather than
// expand, which is the failure mode we want from hostile input.
func parseZoneXML(content []byte) (zoneXML, bool) {
	var z zoneXML
	dec := xml.NewDecoder(bytes.NewReader(content))
	if err := dec.Decode(&z); err != nil {
		return zoneXML{}, false
	}
	return z, true
}

// mergeZone copies the parsed fields onto the zone record, sanitizing every
// string the file provided.
func mergeZone(z hostdoc.FirewalldZone, x zoneXML) hostdoc.FirewalldZone {
	z.Target = sanitizeName(x.Target)
	for _, s := range x.Services {
		z.Services = append(z.Services, sanitizeName(s.Name))
	}
	for _, p := range x.Ports {
		z.Ports = append(z.Ports, hostdoc.FirewalldPort{
			Port:     sanitizeName(p.Port),
			Protocol: sanitizeName(p.Protocol),
		})
	}
	for _, i := range x.Interfaces {
		z.Interfaces = append(z.Interfaces, sanitizeName(i.Name))
	}
	for _, s := range x.Sources {
		z.SourceAddrs = append(z.SourceAddrs, sanitizeName(s.Address))
	}
	z.Masquerade = x.Masquerade != nil
	z.Forward = x.Forward != nil
	for _, f := range x.ForwardPorts {
		z.ForwardPorts = append(z.ForwardPorts, hostdoc.FirewalldForward{
			Port:     sanitizeName(f.Port),
			Protocol: sanitizeName(f.Protocol),
			ToPort:   sanitizeName(f.ToPort),
			ToAddr:   sanitizeName(f.ToAddr),
		})
	}
	return z
}
