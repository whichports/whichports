package hostdoc

import (
	"fmt"
	"strings"
)

// PackagesSection is which package the host's own package database says owns
// the unit file, and the program, of each systemd service behind a listening
// socket. It exists so the control plane can match an installed version
// against the distribution's own security data (docs/RECORD.md 4.218 and
// 4.222).
//
// **It is evidence, never an attribution** (PRODUCT.md 4e, principle 4). The
// agent reports what dpkg's records say about three paths and stops there. The
// rule that turns that into "this port runs this package" is the control
// plane's, because a wrong package is worse than none, and the rule may change
// without an agent release: a package is named only when ExecStart names a
// compiled program and that program and the unit file come from one source
// package. PostgreSQL on Debian is the case that rule refuses on purpose: its
// unit file and the script ExecStart names belong to postgresql-common, while
// the server itself is postgresql-15, a different source (measured on Debian
// 12 and Ubuntu 24.04 on 2026-10-02). Its ExecStart also carries the "-"
// prefix, so the agent names no program for it at all (re-read 2026-10-03).
//
// Only dpkg is read. The RHEL family keeps its records in an SQLite file that
// Go's standard library cannot read, and that is a dependency decision taken
// separately, so on those hosts the dpkg sources read not_present and Units is
// empty.
//
// Added 2026-10-03 under the additive rule (PRODUCT.md 4e, principle 1). A
// control plane that does not know the section stores the document and never
// reads it.
type PackagesSection struct {
	Section
	// Sources carries one verdict per file or directory read, keyed by
	// PackageSources. Only dpkg_status and dpkg_info decide the section's own
	// status: os_release and dpkg_diversions are carried beside them the way
	// passwd is carried beside the socket tables.
	Sources map[string]Section `json:"sources,omitempty"`
	// Distribution is what os-release says this host is, which is how the
	// control plane knows whose security data applies. Nil when neither
	// os-release file could be read.
	Distribution *Distribution `json:"distribution,omitempty"`
	// Units has one entry per service unit behind a listening socket, sorted
	// by name. It is empty unless dpkg's file lists were read in full and its
	// diversions file was read or is absent, because an owner list read from
	// half a database could miss the second owner of a path, and a path that
	// is diverted would be attributed to a package whose file is no longer
	// the one there.
	Units []UnitPackage `json:"units,omitempty"`
	// UnitsCut is true when the host had more service units behind listening
	// sockets than MaxPackageUnits and the rest were left out. The ones kept
	// are the first by name.
	UnitsCut bool `json:"units_cut,omitempty"`
	// Offers has one entry for each package that owns a unit file or a
	// program in Units, sorted by name: what this host's own apt lists offer
	// for it (docs/RECORD.md 4.437). It is empty unless the apt_lists source
	// reads collected, which means every list in apt's folder was read whole.
	// A version standing in the one list that was not read would otherwise
	// be reported as not offered.
	Offers []PackageOffers `json:"offers,omitempty"`
	// OffersCut is true when Units named more packages than MaxOfferPackages
	// and the rest were left out. The ones kept are the first by name.
	OffersCut bool `json:"offers_cut,omitempty"`
}

// PackageSources are the only keys allowed in PackagesSection.Sources.
//
//	os_release       /etc/os-release, or /usr/lib/os-release when the first
//	                 is missing, which is the order os-release(5) gives
//	dpkg_status      /var/lib/dpkg/status, one stanza per package
//	dpkg_info        /var/lib/dpkg/info, whose *.list files name every path
//	                 each package installed
//	dpkg_diversions  /var/lib/dpkg/diversions, paths another package or the
//	                 administrator has moved aside
//	apt_lists        /var/lib/apt/lists, the package lists apt fetched from
//	                 each archive this host is set up with. Collected only
//	                 when every list in it was read whole
var PackageSources = []string{"os_release", "dpkg_status", "dpkg_info", "dpkg_diversions", "apt_lists"}

// The caps below bound what one host can put in this section. A host with
// hundreds of listening services, or a unit file naming a very long path,
// must not grow the report past what the control plane's ingest accepts, and
// whatever a cap cuts is reported as cut, never dropped silently.
const (
	// MaxPackageUnits is how many service units one report carries.
	MaxPackageUnits = 256
	// MaxPackagePathLen bounds each reported path in bytes. Real unit files
	// and programs sit at well under a hundred bytes, so a longer path is
	// left out and the entry says over_cap.
	MaxPackagePathLen = 512
	// MaxPackageFieldLen bounds each package name, version, source and
	// architecture in bytes.
	MaxPackageFieldLen = 128
	// MaxOwnersPerPath is how many owning packages are listed per path. A
	// path with more than one owner can name no single package anyway, so
	// two is enough to show it has several.
	MaxOwnersPerPath = 2
	// MaxUnitNameLen is systemd's own limit: "The total length of the unit
	// name including the suffix must not exceed 255 characters"
	// (systemd.unit(5), read on Debian 12's systemd 252 on 2026-10-03).
	MaxUnitNameLen = 255
	// MaxDistributionFieldLen bounds each os-release value carried.
	MaxDistributionFieldLen = 64
	// MaxOfferPackages is how many packages one report carries offers for.
	MaxOfferPackages = 256
	// MaxOffersPerPackage is how many versions are listed for one package.
	// An archive of a distribution's own offers one version of a package,
	// and a host has a handful of them, so sixteen is far past what a real
	// host shows (measured on 2026-10-06: three for nginx on Ubuntu 24.04).
	MaxOffersPerPackage = 16
)

// UnitPackageFindings is the closed list of values UnitPackage.Finding takes,
// in the order the collector checks them. It is the one place the agent
// defines them. The first finding that applies is the one reported, so an
// entry carries exactly one.
//
//	complete                 every step below had an answer, and the owners
//	                         of the unit file and the program are listed
//	no_unit_file             no file for the unit, or for its template, in
//	                         the unit directories read
//	unit_file_not_read       a file was found and not read: masked, a
//	                         symbolic link, unreadable, or past the size cap
//	drop_in_not_read         a drop-in directory or file that applies to the
//	                         unit could not be read
//	drop_in_sets_exec_start  a drop-in assigns ExecStart=, so the unit file
//	                         does not say what runs
//	no_exec_start            the unit file assigns no ExecStart=
//	several_exec_start       more than one command line
//	exec_start_prefixed      the command starts with one of systemd's special
//	                         executable prefixes (@ - : + !)
//	exec_start_not_a_path    the command is not a plain absolute path: a bare
//	                         file name, quoted, or carrying a specifier, a
//	                         variable or an escape
//	over_cap                 a path, a package field or an owner list was past
//	                         its cap and was left out
//	record_malformed         a package field held a space or a byte outside
//	                         printable ASCII and was left out
//
// A reader that meets a value it does not know treats the entry as naming no
// package, never as an error and never as a match: the list can grow in a
// later agent.
var UnitPackageFindings = []string{
	"complete",
	"no_unit_file",
	"unit_file_not_read",
	"drop_in_not_read",
	"drop_in_sets_exec_start",
	"no_exec_start",
	"several_exec_start",
	"exec_start_prefixed",
	"exec_start_not_a_path",
	"over_cap",
	"record_malformed",
}

// ProgramKinds are the only values UnitPackage.ProgramKind takes, read from
// the first bytes of the file the program path leads to.
//
//	elf       the four bytes every ELF file starts with, a compiled program
//	script    "#!", a script that names its own interpreter
//	other     a regular file that is neither
//	not_read  missing, not a regular file, or not readable by the agent
var ProgramKinds = []string{"elf", "script", "other", "not_read"}

// Distribution is three os-release fields, each verbatim and each present
// only when it fits the character set os-release(5) defines for all three:
// lower-case letters, digits, ".", "_" and "-", and no spaces (read on Debian
// 12's systemd 252 on 2026-10-03). A value outside that set is left out
// rather than cleaned up into something the file did not say.
type Distribution struct {
	// ID is "debian" or "ubuntu", for example.
	ID string `json:"id,omitempty"`
	// VersionID is "12" or "24.04", for example. Debian testing and
	// unstable carry none.
	VersionID string `json:"version_id,omitempty"`
	// VersionCodename is "bookworm" or "noble", for example.
	VersionCodename string `json:"version_codename,omitempty"`
}

// UnitPackage is the evidence for one service unit behind a listening socket.
type UnitPackage struct {
	// Unit is the service unit's name, "ssh.service" or
	// "postgresql@15-main.service".
	Unit string `json:"unit"`
	// Finding is one of UnitPackageFindings.
	Finding string `json:"finding"`
	// UnitFile is the file systemd loads for the unit: the first one found in
	// the unit directories' load order, the literal name before the template
	// (systemd.unit(5)). Nil when there is none.
	UnitFile *OwnedPath `json:"unit_file,omitempty"`
	// Program is the program ExecStart names. Only the path: the arguments
	// stay on the host, because they can hold a password or a token. Nil
	// unless the unit file was read and named exactly one plain absolute
	// path.
	Program *OwnedPath `json:"program,omitempty"`
	// ProgramKind is one of ProgramKinds, set exactly when Program is.
	ProgramKind string `json:"program_kind,omitempty"`
	// ProgramTarget is where Program leads when it is a symbolic link, which
	// is the file that actually runs. On Debian /usr/bin/redis-server is a
	// link to redis-check-rdb (measured 2026-10-02), and both are owned, so
	// both are reported. Nil when Program is not a link or the link leads
	// nowhere.
	ProgramTarget *OwnedPath `json:"program_target,omitempty"`
}

// OwnedPath is a path and what dpkg's records say about it.
type OwnedPath struct {
	// Path is absolute, as the host knows it.
	Path string `json:"path"`
	// Owners are the packages whose file list names Path, under either of
	// its two spellings on a merged-/usr host, at most MaxOwnersPerPath.
	// Empty when no package names it, which is what a file installed by hand
	// reads.
	Owners []Package `json:"owners,omitempty"`
	// Diverted is true when dpkg's diversions file moves this path aside, so
	// the file at Path is not necessarily the one any owner shipped.
	Diverted bool `json:"diverted,omitempty"`
}

// Package is one stanza of dpkg's status file, the fields read verbatim.
type Package struct {
	// Name is the package's name, from the name of its file list.
	Name string `json:"name"`
	// Architecture is the stanza's Architecture field.
	Architecture string `json:"architecture,omitempty"`
	// Installed is true when the stanza's Status ends "ok installed": the
	// flag dpkg(1) calls "in a known state" and the state it calls
	// "correctly unpacked and configured" (dpkg 1.21.22, read 2026-10-03).
	// The first word, the selection state, is not looked at: dpkg(1) keeps
	// it apart from the package state, which is the third word. False
	// for any other state, and when no stanza was found for the file list.
	Installed bool `json:"installed"`
	// Version is the stanza's Version field.
	Version string `json:"version,omitempty"`
	// Source and SourceVersion are the stanza's Source field, verbatim and
	// split in two. deb-control(5): the source package's name appears "if it
	// is different than the name of the package itself", followed by a
	// version in parentheses when "the source version differs from the
	// binary version". So an empty Source means the package's own name, and
	// an empty SourceVersion means Version. That reading is left to the
	// control plane rather than filled in here.
	Source        string `json:"source,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
}

// OfferArchives is the closed list of words an archive is said by. An archive
// says a good deal about itself in its own Release file, and all of it is
// text its owner wrote: for an archive a company runs for itself, that
// company's words. None of that leaves the host (SI-8). The collector holds
// what the archive says against this list and reports the one word, and an
// archive that fits none of the three gives no Offer at all.
//
//	debian           Origin "Debian", Label "Debian", and the Codename is the
//	                 host's release or that with "-updates"
//	debian-security  Origin "Debian", Label "Debian-Security", Codename the
//	                 host's release with "-security"
//	ubuntu           Origin "Ubuntu", Label "Ubuntu", Codename the host's
//	                 release
//
// Read from each archive's InRelease on Debian 12 and Ubuntu 24.04 installs
// on 2026-10-06 (docs/RECORD.md 4.418).
//
// A list's versions are an archive's only when that archive's Release file
// names the list among its files. A list no Release file names is none of
// the three, whatever archive its name starts with.
var OfferArchives = []string{"debian", "debian-security", "ubuntu"}

// PackageOffers is what this host's apt lists say about one package.
type PackageOffers struct {
	// Name is the package's name, as Units names it.
	Name string `json:"name"`
	// Offered are the versions the distribution's own archives offer for it,
	// sorted by archive and then by version as text, each once.
	Offered []Offer `json:"offered,omitempty"`
	// OfferedCut is true when there were more than MaxOffersPerPackage and
	// the rest were left out.
	OfferedCut bool `json:"offered_cut,omitempty"`
	// OtherOffers is true when an archive that is not one of OfferArchives
	// offers this package at all. Which archive, and which versions, stays
	// on the host.
	OtherOffers bool `json:"other_offers"`
	// OtherOffersInstalled is true when such an archive offers the very
	// version that is installed, which is how a package that did not come
	// from the distribution is told from one that did.
	OtherOffersInstalled bool `json:"other_offers_installed"`
}

// Offer is one version one of the distribution's own archives offers.
type Offer struct {
	// Version is the list's Version field. A version of a distribution's own
	// archive is a public fact.
	Version string `json:"version"`
	// Archive is one of OfferArchives.
	Archive string `json:"archive"`
	// NotAutomatic and ButAutomaticUpgrades are the archive's two fields of
	// those names, yes or no. Ubuntu's backports say the same Origin, Label
	// and Codename as its updates and differ only in these two (read on
	// 2026-10-06), and apt does not install from such an archive by itself.
	NotAutomatic         bool `json:"not_automatic"`
	ButAutomaticUpgrades bool `json:"but_automatic_upgrades"`
}

// PackageVersion reports whether s has the shape deb-version(7) gives a
// version: ASCII letters and digits and the marks ". + - ~", with ":" after
// an epoch, starting with a letter or a digit, at most MaxPackageFieldLen
// bytes. The collector keeps a version from a list, and one read back from
// the file the agent keeps beside its state file, only when this accepts it.
func PackageVersion(s string) bool {
	if s == "" || len(s) > MaxPackageFieldLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '+' || c == '-' || c == '~' || c == ':'):
		default:
			return false
		}
	}
	return true
}

// checkOffers is the marshaller's check on what the apt lists offer.
func checkOffers(p *PackagesSection) error {
	if len(p.Offers) == 0 && !p.OffersCut {
		return nil
	}
	// Offers are a claim about every list. Without all of them read there
	// is no such claim to make.
	if p.Sources["apt_lists"].Status != StatusCollected {
		return fmt.Errorf("hostdoc: packages carries offers and its apt_lists source is not collected")
	}
	if len(p.Offers) > MaxOfferPackages {
		return fmt.Errorf("hostdoc: packages carries offers for %d packages, the cap is %d", len(p.Offers), MaxOfferPackages)
	}
	for i, o := range p.Offers {
		if !PackageText(o.Name) {
			return fmt.Errorf("hostdoc: packages offers name %q is not bounded printable text", o.Name)
		}
		if i > 0 && p.Offers[i-1].Name >= o.Name {
			return fmt.Errorf("hostdoc: packages offers are not sorted and unique at %q", o.Name)
		}
		if o.OtherOffersInstalled && !o.OtherOffers {
			return fmt.Errorf("hostdoc: packages offers for %s say another archive offers the installed version and offers nothing", o.Name)
		}
		if len(o.Offered) > MaxOffersPerPackage {
			return fmt.Errorf("hostdoc: packages offers for %s list %d versions, the cap is %d", o.Name, len(o.Offered), MaxOffersPerPackage)
		}
		for j, v := range o.Offered {
			if !inList(v.Archive, OfferArchives) {
				return fmt.Errorf("hostdoc: packages offers for %s name an archive that is not one of the closed list", o.Name)
			}
			if !PackageVersion(v.Version) {
				return fmt.Errorf("hostdoc: packages offers for %s carry a version that has not the shape of one", o.Name)
			}
			if j > 0 && !OfferBefore(o.Offered[j-1], v) {
				return fmt.Errorf("hostdoc: packages offers for %s are not sorted and unique", o.Name)
			}
		}
	}
	return nil
}

// OfferBefore is the order Offered is kept in: by archive, then by version
// as text, then by the two flags. It is only an order, so that the same
// lists always give the same bytes. Which version is the newer one is the
// control plane's to work out.
func OfferBefore(a, b Offer) bool {
	if a.Archive != b.Archive {
		return a.Archive < b.Archive
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.NotAutomatic != b.NotAutomatic {
		return !a.NotAutomatic
	}
	return !a.ButAutomaticUpgrades && b.ButAutomaticUpgrades
}

// checkPackages is the marshaller's last check on this section. Everything
// the collector already guarantees is checked again here, so a programming
// mistake fails a test rather than putting an undefined value, an unbounded
// string or a contradiction on the wire (SI-8).
func checkPackages(p *PackagesSection) error {
	if err := checkSection("packages", p.Section); err != nil {
		return err
	}
	if err := checkSources("packages", p.Sources, PackageSources); err != nil {
		return err
	}
	if d := p.Distribution; d != nil {
		for _, v := range []string{d.ID, d.VersionID, d.VersionCodename} {
			if v != "" && !DistributionValue(v) {
				return fmt.Errorf("hostdoc: packages distribution value %q is not an os-release identifier", v)
			}
		}
	}
	if len(p.Units) > MaxPackageUnits {
		return fmt.Errorf("hostdoc: packages carries %d units, the cap is %d", len(p.Units), MaxPackageUnits)
	}
	for i, u := range p.Units {
		if i > 0 && p.Units[i-1].Unit >= u.Unit {
			return fmt.Errorf("hostdoc: packages units are not sorted and unique at %q", u.Unit)
		}
		if err := checkUnitPackage(u); err != nil {
			return err
		}
	}
	return checkOffers(p)
}

func checkUnitPackage(u UnitPackage) error {
	if !ServiceUnitName(u.Unit) {
		return fmt.Errorf("hostdoc: packages unit %q is not a service unit name", u.Unit)
	}
	if !inList(u.Finding, UnitPackageFindings) {
		return fmt.Errorf("hostdoc: packages %s finding %q is not a defined finding", u.Unit, u.Finding)
	}
	// complete means every step had an answer, so both paths are there.
	if u.Finding == "complete" && (u.UnitFile == nil || u.Program == nil) {
		return fmt.Errorf("hostdoc: packages %s is complete without a unit file and a program", u.Unit)
	}
	if u.Finding == "no_unit_file" && u.UnitFile != nil {
		return fmt.Errorf("hostdoc: packages %s has no unit file and reports one", u.Unit)
	}
	if (u.Program == nil) != (u.ProgramKind == "") {
		return fmt.Errorf("hostdoc: packages %s program and program_kind disagree", u.Unit)
	}
	if u.ProgramKind != "" && !inList(u.ProgramKind, ProgramKinds) {
		return fmt.Errorf("hostdoc: packages %s program_kind %q is not a defined kind", u.Unit, u.ProgramKind)
	}
	if u.ProgramTarget != nil && u.Program == nil {
		return fmt.Errorf("hostdoc: packages %s has a program target without a program", u.Unit)
	}
	for _, op := range []*OwnedPath{u.UnitFile, u.Program, u.ProgramTarget} {
		if op == nil {
			continue
		}
		if err := checkOwnedPath(u.Unit, op); err != nil {
			return err
		}
	}
	return nil
}

func checkOwnedPath(unit string, op *OwnedPath) error {
	if op.Path == "" || op.Path[0] != '/' {
		return fmt.Errorf("hostdoc: packages %s path %q is not absolute", unit, op.Path)
	}
	if len(op.Path) > MaxPackagePathLen {
		return fmt.Errorf("hostdoc: packages %s path is %d bytes, the cap is %d", unit, len(op.Path), MaxPackagePathLen)
	}
	if len(op.Owners) > MaxOwnersPerPath {
		return fmt.Errorf("hostdoc: packages %s path %q lists %d owners, the cap is %d", unit, op.Path, len(op.Owners), MaxOwnersPerPath)
	}
	for _, o := range op.Owners {
		if o.Name == "" {
			return fmt.Errorf("hostdoc: packages %s path %q has an owner with no name", unit, op.Path)
		}
		for _, v := range []string{o.Name, o.Architecture, o.Version, o.Source, o.SourceVersion} {
			if v != "" && !PackageText(v) {
				return fmt.Errorf("hostdoc: packages %s owner field %q is not bounded printable text", unit, v)
			}
		}
		if o.SourceVersion != "" && o.Source == "" {
			return fmt.Errorf("hostdoc: packages %s owner %s has a source version without a source", unit, o.Name)
		}
	}
	return nil
}

// ServiceUnitName reports whether s is a name systemd would accept for a
// service unit: at most MaxUnitNameLen bytes, ending in ".service", made of
// the characters systemd.unit(5) lists for a unit name prefix (ASCII letters,
// digits, ":", "-", "_", "." and "\") plus the single "@" of a template or an
// instance. The collector and the marshaller share it, so the agent never
// looks up, or reports, a name that is not one.
func ServiceUnitName(s string) bool {
	prefix, ok := strings.CutSuffix(s, ".service")
	if !ok || prefix == "" || len(s) > MaxUnitNameLen {
		return false
	}
	if strings.Count(prefix, "@") > 1 || strings.HasPrefix(prefix, "@") {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == ':', c == '-', c == '_', c == '.', c == '\\', c == '@':
		default:
			return false
		}
	}
	return true
}

// PackageText reports whether s is a value this section will carry for a
// package field: at most MaxPackageFieldLen bytes of printable ASCII with no
// space. A field that is not is left out and the entry says over_cap or
// record_malformed, rather than sanitized into a name no package has.
func PackageText(s string) bool {
	if s == "" || len(s) > MaxPackageFieldLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// DistributionValue reports whether s fits the os-release(5) character set
// for ID, VERSION_ID and VERSION_CODENAME, within MaxDistributionFieldLen.
// The collector keeps a value only when this accepts it.
func DistributionValue(s string) bool {
	if s == "" || len(s) > MaxDistributionFieldLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
