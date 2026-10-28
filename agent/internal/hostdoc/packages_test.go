package hostdoc

import (
	"encoding/json"
	"strings"
	"testing"
)

// The packages section's contract: what the marshaller refuses, what it
// carries through, and how large the section can ever be.

// ingestLimit is the control plane's refusal size for one report,
// MAX_DOCUMENT_BYTES in controlplane/app/ingest.py (8 MiB, read 2026-10-03).
// It is repeated here, not imported, because the agent is a module of its own
// and is meant to become public on its own.
const ingestLimit = 8 << 20

func goodUnit() UnitPackage {
	owner := Package{Name: "openssh-server", Architecture: "arm64", Installed: true,
		Version: "1:9.0p1-1", Source: "openssh"}
	return UnitPackage{
		Unit:        "ssh.service",
		Finding:     "complete",
		UnitFile:    &OwnedPath{Path: "/usr/lib/systemd/system/ssh.service", Owners: []Package{owner}},
		Program:     &OwnedPath{Path: "/usr/sbin/sshd", Owners: []Package{owner}},
		ProgramKind: "elf",
	}
}

func goodPackages() *PackagesSection {
	return &PackagesSection{
		Section: Section{Status: StatusCollected},
		Sources: map[string]Section{
			"os_release": {Status: StatusCollected}, "dpkg_status": {Status: StatusCollected},
			"dpkg_info": {Status: StatusCollected}, "dpkg_diversions": {Status: StatusNotPresent},
		},
		Distribution: &Distribution{ID: "debian", VersionID: "12", VersionCodename: "bookworm"},
		Units:        []UnitPackage{goodUnit()},
	}
}

func marshalPackages(p *PackagesSection) ([]byte, error) {
	d := New("h", 1)
	d.Packages = p
	return Marshal(d)
}

func TestAGoodPackagesSectionRoundTrips(t *testing.T) {
	b, err := marshalPackages(goodPackages())
	if err != nil {
		t.Fatal(err)
	}
	var back Document
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	got := back.Packages.Units[0]
	if got.Unit != "ssh.service" || got.Program.Owners[0].Source != "openssh" || !got.Program.Owners[0].Installed {
		t.Errorf("round trip lost a field: %+v", got)
	}
	// installed is written even when false, so a reader never has to guess
	// what an absent field meant
	p := goodPackages()
	p.Units[0].Program.Owners[0].Installed = false
	b, _ = marshalPackages(p)
	if !strings.Contains(string(b), `"installed": false`) {
		t.Errorf("installed false was left out:\n%s", b)
	}
}

func TestAnOldDocumentWithoutPackagesStillMarshals(t *testing.T) {
	b, err := Marshal(New("h", 1))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "packages") {
		t.Errorf("a document without the section carries its key:\n%s", b)
	}
}

func TestEveryFindingAndKindIsAccepted(t *testing.T) {
	for _, f := range UnitPackageFindings {
		p := goodPackages()
		u := &p.Units[0]
		u.Finding = f
		if f != "complete" && f != "over_cap" && f != "record_malformed" {
			u.Program, u.ProgramKind = nil, ""
		}
		if f == "no_unit_file" {
			u.UnitFile = nil
		}
		if _, err := marshalPackages(p); err != nil {
			t.Errorf("finding %q refused: %v", f, err)
		}
	}
	for _, k := range ProgramKinds {
		p := goodPackages()
		p.Units[0].ProgramKind = k
		if _, err := marshalPackages(p); err != nil {
			t.Errorf("kind %q refused: %v", k, err)
		}
	}
}

func TestTheFindingsAreOneClosedList(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range UnitPackageFindings {
		if seen[f] {
			t.Errorf("%q is in the list twice", f)
		}
		seen[f] = true
	}
	if UnitPackageFindings[0] != "complete" {
		t.Error("complete is the first finding, the one that says every step had an answer")
	}
}

func TestMarshalRefusesWhatThePackagesSectionMayNotCarry(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	cases := map[string]func(p *PackagesSection){
		"an undefined status":     func(p *PackagesSection) { p.Status = "made-up" },
		"collected with a cause":  func(p *PackagesSection) { p.Cause = CausePermission },
		"an unknown source key":   func(p *PackagesSection) { p.Sources["rpmdb"] = Section{Status: StatusCollected} },
		"a bad source verdict":    func(p *PackagesSection) { p.Sources["dpkg_info"] = Section{Status: "x"} },
		"an upper-case id":        func(p *PackagesSection) { p.Distribution.ID = "Debian" },
		"a space in a version id": func(p *PackagesSection) { p.Distribution.VersionID = "12 lts" },
		"a codename past its cap": func(p *PackagesSection) { p.Distribution.VersionCodename = long(MaxDistributionFieldLen + 1) },
		"an undefined finding":    func(p *PackagesSection) { p.Units[0].Finding = "probably" },
		"an empty finding":        func(p *PackagesSection) { p.Units[0].Finding = "" },
		"an undefined kind":       func(p *PackagesSection) { p.Units[0].ProgramKind = "binary" },
		"a kind with no program":  func(p *PackagesSection) { p.Units[0].Program = nil },
		"a program with no kind":  func(p *PackagesSection) { p.Units[0].ProgramKind = "" },
		"a target with no program": func(p *PackagesSection) {
			p.Units[0].Program, p.Units[0].ProgramKind = nil, ""
			p.Units[0].Finding = "no_exec_start"
			p.Units[0].ProgramTarget = &OwnedPath{Path: "/usr/bin/x"}
		},
		"complete with no program":   func(p *PackagesSection) { p.Units[0].Program, p.Units[0].ProgramKind = nil, "" },
		"complete with no unit file": func(p *PackagesSection) { p.Units[0].UnitFile = nil },
		"no unit file and one":       func(p *PackagesSection) { p.Units[0].Finding = "no_unit_file" },
		"a socket unit":              func(p *PackagesSection) { p.Units[0].Unit = "ssh.socket" },
		"a unit name with a space":   func(p *PackagesSection) { p.Units[0].Unit = "my app.service" },
		"a unit name with a slash":   func(p *PackagesSection) { p.Units[0].Unit = "../x.service" },
		"two @ in a unit name":       func(p *PackagesSection) { p.Units[0].Unit = "a@b@c.service" },
		"a unit name past 255":       func(p *PackagesSection) { p.Units[0].Unit = long(248) + ".service" },
		"units out of order":         func(p *PackagesSection) { u := goodUnit(); u.Unit = "a.service"; p.Units = append(p.Units, u) },
		"a unit twice":               func(p *PackagesSection) { p.Units = append(p.Units, goodUnit()) },
		"a relative path":            func(p *PackagesSection) { p.Units[0].Program.Path = "usr/sbin/sshd" },
		"an empty path":              func(p *PackagesSection) { p.Units[0].UnitFile.Path = "" },
		"a path past its cap":        func(p *PackagesSection) { p.Units[0].Program.Path = "/" + long(MaxPackagePathLen) },
		"three owners": func(p *PackagesSection) {
			o := p.Units[0].Program.Owners[0]
			p.Units[0].Program.Owners = []Package{o, o, o}
		},
		"an owner with no name":         func(p *PackagesSection) { p.Units[0].Program.Owners[0].Name = "" },
		"a name with a space":           func(p *PackagesSection) { p.Units[0].Program.Owners[0].Name = "open ssh" },
		"a version with a control byte": func(p *PackagesSection) { p.Units[0].Program.Owners[0].Version = "1.0\x1b[31m" },
		"a version past its cap":        func(p *PackagesSection) { p.Units[0].Program.Owners[0].Version = long(MaxPackageFieldLen + 1) },
		"non-ascii in a source":         func(p *PackagesSection) { p.Units[0].Program.Owners[0].Source = "opénssh" },
		"a source version alone":        func(p *PackagesSection) { o := &p.Units[0].Program.Owners[0]; o.Source = ""; o.SourceVersion = "1.0" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := goodPackages()
			mutate(p)
			if _, err := marshalPackages(p); err == nil {
				t.Fatal("Marshal must refuse it")
			}
		})
	}
}

func TestTooManyUnitsAreRefused(t *testing.T) {
	p := goodPackages()
	p.Units = nil
	for i := 0; i <= MaxPackageUnits; i++ {
		u := goodUnit()
		u.Unit = "u" + strings.Repeat("0", 4-len(itoa(i))) + itoa(i) + ".service"
		p.Units = append(p.Units, u)
	}
	if _, err := marshalPackages(p); err == nil {
		t.Fatal("one unit past the cap must be refused")
	}
	p.Units = p.Units[:MaxPackageUnits]
	if _, err := marshalPackages(p); err != nil {
		t.Fatalf("the cap itself must be accepted: %v", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for ; i > 0; i /= 10 {
		s = string(rune('0'+i%10)) + s
	}
	return s
}

// The worst a host can make this section is every cap at once: the most
// units, each with three paths at their longest, each path with the most
// owners, each owner with every field at its longest. That must leave room
// under the ingest's limit for everything else in the report.
func TestTheLargestPossibleSectionStaysWellUnderTheIngestLimit(t *testing.T) {
	field := strings.Repeat("9", MaxPackageFieldLen)
	owner := Package{Name: field, Architecture: field, Installed: true, Version: field,
		Source: field, SourceVersion: field}
	path := func(c string) *OwnedPath {
		return &OwnedPath{Path: "/" + strings.Repeat(c, MaxPackagePathLen-1),
			Owners: []Package{owner, owner}, Diverted: true}
	}
	p := goodPackages()
	p.UnitsCut = true
	p.Units = nil
	for i := 0; i < MaxPackageUnits; i++ {
		name := strings.Repeat("u", MaxUnitNameLen-len(".service")-4) + strings.Repeat("0", 4-len(itoa(i))) + itoa(i) + ".service"
		p.Units = append(p.Units, UnitPackage{Unit: name, Finding: "over_cap",
			UnitFile: path("a"), Program: path("b"), ProgramKind: "not_read", ProgramTarget: path("c")})
	}
	b, err := marshalPackages(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > ingestLimit/2 {
		t.Errorf("the largest section is %d bytes, more than half of the ingest's %d", len(b), ingestLimit)
	}
	t.Logf("the largest possible packages section marshals to %d bytes", len(b))
}
