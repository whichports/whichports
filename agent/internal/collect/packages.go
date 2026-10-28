// This file is the package collector: which package dpkg's own records say
// owns the unit file and the program of each systemd service behind a
// listening socket. It reads dpkg's files directly and never runs dpkg-query,
// because the agent executes nothing (PRODUCT.md 4e).
//
// It reports evidence and stops. The rule that names a package for a port
// belongs to the control plane, see hostdoc.PackagesSection for why.
//
// Every build holds this reader since 2026-10-12, when the security data
// check shipped: the control plane matching these versions against the
// distribution's own security data (hostdoc.PackagesSection). Until then it
// stood behind a build tag that no release was built with, so no published
// agent read a package or a version (docs/RECORD.md 4.369 and 4.385,
// docs/SPEC-packages-switch.md). Nothing about how a release is built
// changed that day.
//
// Every file it reads was measured world readable on Debian 12 and 13 and on
// Ubuntu 24.04 and 26.04 on 2026-10-02: /var/lib/dpkg/status, the *.list
// files under /var/lib/dpkg/info and /var/lib/dpkg/diversions are 0644 root,
// their directories 0755, and so are the unit files. So it costs the agent's
// unprivileged user nothing.
package collect

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// dpkgDir is dpkg's administrative directory, relative to the collector's
// root. dpkg(1) names /var/lib/dpkg/status in its FILES section.
const dpkgDir = "var/lib/dpkg"

// The read caps. Each file is refused rather than truncated past its cap, for
// the reason readCapped gives: half a file read as the whole one is a
// confident wrong answer. The measured sizes are far below them: the four
// base images above hold 180 to 330 KB of file lists in all. They are
// variables only so the tests can lower them.
var (
	// maxStatusBytes bounds /var/lib/dpkg/status.
	maxStatusBytes = 64 << 20
	// maxListBytes bounds one *.list file.
	maxListBytes = 64 << 20
	// maxListTotalBytes bounds all *.list files together, so a host with an
	// enormous package set cannot make one run read without end.
	maxListTotalBytes = 512 << 20
)

// mergedUsrDirs are the top-level directories that a merged-/usr host makes
// symbolic links into /usr. A package's file list can name a path under
// either spelling: Debian 12's own lists still name 13 files under /bin/, and
// its systemd units under /lib/systemd/system, while the unit directory read
// here is /usr/lib/systemd/system. Measured on 2026-10-02: /bin, /sbin and
// /lib link to usr/bin, usr/sbin and usr/lib on Debian 12 and 13 and Ubuntu
// 24.04 and 26.04, and /lib64 to usr/lib64 on Ubuntu 26.04 for amd64.
//
// The second spelling is only tried on a host where the link is really there,
// read with readlink, so a host that is not merged is never read as if it were.
var mergedUsrDirs = []string{"bin", "sbin", "lib", "lib64"}

// CollectPackages reports what dpkg's records say about each service unit in
// units, which ListeningServiceUnits builds from the two socket sections, and
// what the host's apt lists offer for the packages those records name
// (aptlists.go).
func CollectPackages(root string, units []string) *hostdoc.PackagesSection {
	sec, _ := CollectPackagesKeeping(root, units, nil)
	return sec
}

// CollectPackagesKeeping is CollectPackages for a caller that keeps what the
// apt lists reader read, so a list that did not change is not read again.
// keptLists is what the last call returned, or nil, and the second result is
// what to keep now: nil when the lists were not read whole, and nothing is
// then worth keeping. This package writes no file. The caller does, beside
// the agent's own state file, and the bytes never leave the host.
func CollectPackagesKeeping(root string, units []string, keptLists []byte) (*hostdoc.PackagesSection, []byte) {
	sec := &hostdoc.PackagesSection{Sources: map[string]hostdoc.Section{}}
	// Until the lists are read, they were not: every way out of this
	// function before that point says so.
	sec.Sources["apt_lists"] = hostdoc.Section{Status: hostdoc.StatusNotCollected}
	var osVerdict hostdoc.Section
	sec.Distribution, osVerdict = readDistribution(root)
	sec.Sources["os_release"] = osVerdict

	lists, infoVerdict := listFileLists(filepath.Join(root, dpkgDir, "info"))
	if infoVerdict.Status != hostdoc.StatusCollected {
		// No file lists, so no owner can be known and nothing else is read.
		// A host of the RHEL family lands here, with every dpkg source
		// not_present.
		sec.Sources["dpkg_info"] = infoVerdict
		sec.Sources["dpkg_status"] = openVerdict(filepath.Join(root, dpkgDir, "status"))
		sec.Sources["dpkg_diversions"] = openVerdict(filepath.Join(root, dpkgDir, "diversions"))
		sec.Section = packageSectionVerdict(sec.Sources)
		return sec, nil
	}

	kept, cut := boundUnits(units)
	sec.UnitsCut = cut
	scan := scanServiceDirs(root)
	evidence := make([]unitEvidence, 0, len(kept))
	for _, name := range kept {
		evidence = append(evidence, readUnitEvidence(root, name, scan))
	}

	merged := mergedUsr(root)
	wanted := map[string]bool{}
	for _, ev := range evidence {
		for _, p := range []string{ev.unitFile, ev.program, ev.target} {
			for _, sp := range spellings(p, merged) {
				wanted[sp] = true
			}
		}
	}
	owners, infoVerdict := scanFileLists(filepath.Join(root, dpkgDir, "info"), lists, wanted)
	sec.Sources["dpkg_info"] = infoVerdict
	diverted, divVerdict := readDiversions(filepath.Join(root, dpkgDir, "diversions"))
	sec.Sources["dpkg_diversions"] = divVerdict
	stanzas, statusVerdict := readStatus(filepath.Join(root, dpkgDir, "status"), ownerNames(owners))
	sec.Sources["dpkg_status"] = statusVerdict
	sec.Section = packageSectionVerdict(sec.Sources)

	// Units are listed only when every file list was read and the diversions
	// are known. Otherwise a path's second owner, or its diversion, could be
	// the part that was not read, and the entry would look complete.
	if infoVerdict.Status != hostdoc.StatusCollected {
		return sec, nil
	}
	if divVerdict.Status != hostdoc.StatusCollected && divVerdict.Status != hostdoc.StatusNotPresent {
		return sec, nil
	}
	db := ownerDB{owners: owners, stanzas: stanzas, diverted: diverted, merged: merged}
	for _, ev := range evidence {
		sec.Units = append(sec.Units, db.unitPackage(ev))
	}
	// The lists are asked only about the packages the units above name.
	var keep []byte
	sec.Offers, sec.OffersCut, sec.Sources["apt_lists"], keep = collectOffers(
		root, sec.Distribution, askedPackages(sec.Units), keptLists)
	return sec, keep
}

// packageSectionVerdict is the section's own status. Only the two sources a
// package can be named from decide it, so a host with no dpkg reads
// not_present even though its os-release was read.
func packageSectionVerdict(sources map[string]hostdoc.Section) hostdoc.Section {
	return aggregateSources(map[string]hostdoc.Section{
		"dpkg_status": sources["dpkg_status"],
		"dpkg_info":   sources["dpkg_info"],
	})
}

// openVerdict reports whether a file is there and readable, without reading
// it, for a source that is not needed on this run but whose verdict still
// belongs in the document.
func openVerdict(path string) hostdoc.Section {
	f, err := os.Open(path)
	if err != nil {
		return fileVerdict(err)
	}
	f.Close()
	return hostdoc.Section{Status: hostdoc.StatusCollected}
}

// ---------------------------------------------------------------- the units

// ListeningServiceUnits names the service units whose packages are worth
// reading: every system service behind a listening socket, and no other.
//
// A listening socket says which service that is in one of two ways. Either
// the kernel reports the socket in the service's own cgroup, or it reports it
// in the cgroup of a socket unit, which is where systemd keeps a socket it
// holds for a service it starts on demand, and the socket unit's file names
// the service. Measured on 2026-10-03 with OpenSSH's ssh.socket enabled and
// ssh.service inactive, on Debian 12 (systemd 252), Debian 13 (systemd 257)
// and Ubuntu 24.04 (systemd 255): the socket on port 22 is reported under
// "/system.slice/ssh.socket".
//
// **A socket unit file on disk names nothing by itself.** Until 2026-10-03
// every service a socket unit handed a declared port to was taken, whether
// or not that socket unit held a socket. So a server with OpenSSH installed
// and not started, whose package ships ssh.socket, sent the package and the
// version of software nothing listened for. A socket unit counts only while
// a listening socket is its own.
//
// A socket counts only when its cgroup is a unit directly inside slices,
// "/system.slice/nginx.service" for example. Under anything else the unit is
// not the host's own: a user's service sits under "user@1000.service", and a
// container running its own systemd sits under a ".scope" or a runtime's
// directory, where "nginx.service" is the container's unit and the host's
// unit file of that name, if there is one, says nothing about it. Those
// sockets read no entry, which the control plane reads as no package, never
// as a guess.
func ListeningServiceUnits(sockets *hostdoc.SocketsSection, socketUnits *hostdoc.SocketUnitsSection) []string {
	set := map[string]bool{}
	// The host's own socket units that hold a listening socket.
	holding := map[string]bool{}
	if sockets != nil {
		for _, s := range sockets.Listening {
			if systemService(s.Cgroup, s.Unit) {
				set[s.Unit] = true
			}
			if systemSocket(s.Cgroup, s.Unit) {
				holding[s.Unit] = true
			}
		}
	}
	if socketUnits != nil {
		for _, u := range socketUnits.Units {
			// A template is a pattern and not a listener, a masked unit is
			// not loaded, and an alias is another name for a unit listed on
			// its own (hostdoc.SocketUnit).
			if !u.Parsed || u.Masked || u.Template || u.AliasOf != "" {
				continue
			}
			if holding[u.Name] && declaresAPort(u.Listen) && hostdoc.ServiceUnitName(u.ServiceUnit) {
				set[u.ServiceUnit] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func systemService(cgroup, unit string) bool {
	return hostdoc.ServiceUnitName(unit) && directlyInSlices(cgroup, unit)
}

// systemSocket is systemService for a socket unit: "/system.slice/ssh.socket".
func systemSocket(cgroup, unit string) bool {
	name, ok := strings.CutSuffix(unit, ".socket")
	return ok && name != "" && directlyInSlices(cgroup, unit)
}

// directlyInSlices reports whether a cgroup path ends in the unit and has
// nothing but slices above it.
func directlyInSlices(cgroup, unit string) bool {
	parts := strings.Split(strings.Trim(cgroup, "/"), "/")
	if parts[len(parts)-1] != unit {
		return false
	}
	for _, p := range parts[:len(parts)-1] {
		if !strings.HasSuffix(p, ".slice") {
			return false
		}
	}
	return true
}

func declaresAPort(listen []hostdoc.SocketUnitListen) bool {
	for _, l := range listen {
		if l.Port > 0 {
			return true
		}
	}
	return false
}

// boundUnits sorts, removes duplicates and names that are not service units,
// and keeps the first MaxPackageUnits.
func boundUnits(units []string) ([]string, bool) {
	set := map[string]bool{}
	for _, u := range units {
		if hostdoc.ServiceUnitName(u) {
			set[u] = true
		}
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	if len(out) > hostdoc.MaxPackageUnits {
		return out[:hostdoc.MaxPackageUnits], true
	}
	return out, false
}

// unitEvidence is what the unit files say about one unit, before any package
// is looked up. Paths are as the host knows them, empty when there is none.
type unitEvidence struct {
	name     string
	finding  string
	unitFile string
	program  string
	kind     string
	target   string
}

// readUnitEvidence follows one unit from its name to the program it starts,
// and stops at the first step with no answer, which becomes the finding.
func readUnitEvidence(root, name string, scan *serviceDirScan) unitEvidence {
	ev := unitEvidence{name: name}
	path, reported, finding := findServiceUnitFile(root, name)
	if finding != "" {
		ev.finding = finding
		return ev
	}
	ev.unitFile = reported
	content, ok := readServiceUnitFile(path)
	if !ok {
		ev.finding = "unit_file_not_read"
		return ev
	}
	if f := scan.dropInFinding(name); f != "" {
		ev.finding = f
		return ev
	}
	finding, program := execStartProgram(content)
	if finding != "complete" {
		ev.finding = finding
		return ev
	}
	if !pathWithinCap(program) {
		ev.finding = "over_cap"
		return ev
	}
	ev.finding = "complete"
	ev.program = program
	ev.kind = programKind(root, program)
	ev.target = linkTarget(root, program)
	if !pathWithinCap(ev.target) {
		ev.target = ""
		ev.finding = "over_cap"
	}
	return ev
}

// pathWithinCap reports whether a path fits MaxPackagePathLen as it will be
// sent, which is after sanitizeName. Each byte that is not UTF-8 becomes a
// three-byte replacement character there, so a path under the cap as read can
// be over it as sent. Measuring the raw path let one through that the
// marshaller then refused, which failed the whole report (found by
// FuzzExecStartProgram).
func pathWithinCap(path string) bool {
	return len(sanitizeName(path)) <= hostdoc.MaxPackagePathLen
}

// findServiceUnitFile finds the file systemd loads for a service unit. The
// directories are the same load path the socket unit collector reads,
// socketUnitDirs, in the same precedence order, because systemd.unit(5) has
// one load path for every unit type. And it looks for the literal name first,
// everywhere, before the template: "If systemd looks for a unit configuration
// file, it will first search for the literal unit name in the file system. If
// that yields no success and the unit name contains an "@" character, systemd
// will look for a unit template that shares the same name but with the
// instance string ... removed" (systemd.unit(5), systemd 252, read
// 2026-10-03).
//
// A directory the agent may not search makes the answer unknowable, because
// the file systemd loads could be the one in it, so it returns
// unit_file_not_read rather than the next file down.
func findServiceUnitFile(root, name string) (path, reported, finding string) {
	names := []string{name}
	if template, ok := serviceTemplateOf(name); ok {
		names = append(names, template)
	}
	for _, n := range names {
		for _, d := range socketUnitDirs {
			p := filepath.Join(root, d.Rel, n)
			_, err := os.Lstat(p)
			if err == nil {
				return p, "/" + d.Rel + "/" + n, ""
			}
			if os.IsPermission(err) {
				return "", "", "unit_file_not_read"
			}
		}
	}
	return "", "", "no_unit_file"
}

// serviceTemplateOf turns "postgresql@15-main.service" into
// "postgresql@.service". A name with no instance is not an instance.
func serviceTemplateOf(name string) (string, bool) {
	base := strings.TrimSuffix(name, ".service")
	prefix, instance, found := strings.Cut(base, "@")
	if !found || instance == "" {
		return "", false
	}
	return prefix + "@.service", true
}

// readServiceUnitFile reads a unit file that is a plain, non-empty regular
// file. Anything else is not read:
//
//   - a symbolic link, because following one is how a unit file could make
//     the agent read a file its own reader did not choose (see
//     unitSymlinkRefused), and an alias or a link to a file outside the unit
//     directories is not what a package installs under the unit's own name
//   - an empty file, which systemd treats as masked (systemd.unit(5)) and so
//     starts nothing
//   - a directory or a device
func readServiceUnitFile(path string) (string, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return "", false
	}
	content, err := readCapped(path)
	if err != nil {
		return "", false
	}
	return string(content), true
}

// execStartProgram reads the program a service unit's ExecStart= names, from
// the [Service] section, under systemd.service(5)'s rules (systemd 252, read
// 2026-10-03):
//
//   - "If the empty string is assigned to this option, the list of commands
//     to start is reset", so an empty assignment clears what came before
//   - assigning it more than once adds a command, and "Multiple command lines
//     may be concatenated in a single directive by separating them with
//     semicolons (these semicolons must be passed as separate words)". Either
//     way that is several commands and no single program
//   - the first word may carry "special executable prefixes", @ - : + and !,
//     which change how it runs. Reported as prefixed rather than stripped
//   - "the first argument must be either an absolute path to an executable or
//     a simple file name without any slashes". A simple file name is looked
//     up in a search path this agent does not reproduce, so only an absolute
//     path counts
//
// The path is only the first word. The arguments are never returned, because
// they can hold a password or a token, and they stay on the host.
func execStartProgram(content string) (finding, program string) {
	section := ""
	var commands []string
	for _, raw := range logicalLines(content) {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && line[len(line)-1] == ']' {
			section = line[1 : len(line)-1]
			continue
		}
		if section != "Service" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) != "ExecStart" {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			commands = nil
			continue
		}
		commands = append(commands, value)
	}
	if len(commands) == 0 {
		return "no_exec_start", ""
	}
	if len(commands) > 1 {
		return "several_exec_start", ""
	}
	words := strings.Fields(commands[0])
	for _, w := range words[1:] {
		if w == ";" {
			return "several_exec_start", ""
		}
	}
	first := words[0]
	if strings.ContainsAny(first[:1], "@-:+!") {
		return "exec_start_prefixed", ""
	}
	if !plainAbsolutePath(first) {
		return "exec_start_not_a_path", ""
	}
	return "complete", first
}

// plainAbsolutePath reports whether a command's first word is an absolute
// path that means what it says. A quote, a "%" specifier, a "$" variable or a
// "\" escape would each need systemd's own expansion to know the real path,
// and a path that cleans to something else (a doubled slash, a "..") is not
// the spelling any package file list uses.
func plainAbsolutePath(p string) bool {
	if len(p) < 2 || p[0] != '/' {
		return false
	}
	if strings.ContainsAny(p, "%$\\\"'") {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return false
		}
	}
	return filepath.Clean(p) == p
}

// programKind reads the first bytes of the file the program path leads to.
//
// The open is non-blocking and the kind is read off the open handle, so a
// path that turns out to be a FIFO cannot hang the run, and a file swapped
// between a check and the open is still checked as what was opened. Four
// bytes are read and only the kind leaves the host.
func programKind(root, program string) string {
	f, err := os.OpenFile(filepath.Join(root, program), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "not_read"
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "not_read"
	}
	head := make([]byte, 4)
	n, _ := io.ReadFull(f, head)
	switch {
	case n == 4 && bytes.Equal(head, []byte("\x7fELF")):
		return "elf"
	case n >= 2 && head[0] == '#' && head[1] == '!':
		return "script"
	default:
		return "other"
	}
}

// linkTarget is where a program path that is a symbolic link leads, resolved
// the way the kernel resolves it, and empty when the path is not a link or
// the chain does not reach a file inside root.
func linkTarget(root, program string) string {
	info, err := os.Lstat(filepath.Join(root, program))
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return ""
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, program))
	if err != nil {
		return ""
	}
	if realRoot == "/" {
		return resolved
	}
	rest, ok := strings.CutPrefix(resolved, realRoot+string(filepath.Separator))
	if !ok {
		return ""
	}
	return "/" + rest
}

// --------------------------------------------------------------- drop-ins

// serviceDirScan is what one listing of the unit directories found that
// bears on a service's ExecStart= beyond its own file: drop-in directories,
// and the alias links whose own drop-ins apply too.
type serviceDirScan struct {
	// dropInDirs maps a drop-in directory's name, "ssh.service.d", to its
	// path in each unit directory where it exists.
	dropInDirs map[string][]string
	// aliases maps a unit file's name to the names of the links that make
	// it an alias: on Debian sshd.service links to ssh.service.
	aliases map[string][]string
	// denied is true when a unit directory exists and could not be listed,
	// so a drop-in in it would go unseen.
	denied bool
}

func scanServiceDirs(root string) *serviceDirScan {
	s := &serviceDirScan{dropInDirs: map[string][]string{}, aliases: map[string][]string{}}
	for _, d := range socketUnitDirs {
		dir := filepath.Join(root, d.Rel)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				s.denied = true
			}
			continue
		}
		for _, e := range entries {
			name := e.Name()
			full := filepath.Join(dir, name)
			if name == "service.d" || strings.HasSuffix(name, ".service.d") {
				if info, err := os.Stat(full); err == nil && info.IsDir() {
					s.dropInDirs[name] = append(s.dropInDirs[name], full)
				}
				continue
			}
			if e.Type()&os.ModeSymlink != 0 && strings.HasSuffix(name, ".service") {
				if dest, err := os.Readlink(full); err == nil {
					target := filepath.Base(dest)
					if strings.HasSuffix(target, ".service") && target != name {
						s.aliases[target] = append(s.aliases[target], name)
					}
				}
			}
		}
	}
	return s
}

// dropInDirNames is every drop-in directory name that can apply to a service
// unit, from systemd.unit(5): the unit's own "foo.service.d", the template's
// for an instance, the ones of every alias, the dashed prefixes ("for a unit
// name foo-bar-baz.service not only the regular drop-in directory
// foo-bar-baz.service.d/ is searched but also both foo-bar-.service.d/ and
// foo-.service.d/"), and the top-level "service.d".
//
// It errs wide on purpose. A dashed prefix is taken at every dash, even one
// inside an instance name, where the manual does not say. A directory that
// does not really apply can only turn an entry into drop_in_sets_exec_start,
// which names no package. Missing one that does apply could name the wrong
// program.
func (s *serviceDirScan) dropInDirNames(name string) []string {
	units := []string{name}
	units = append(units, s.aliases[name]...)
	if template, ok := serviceTemplateOf(name); ok {
		units = append(units, template)
		units = append(units, s.aliases[template]...)
	}
	set := map[string]bool{"service.d": true}
	for _, u := range units {
		set[u+".d"] = true
		prefix := strings.TrimSuffix(u, ".service")
		for i := 0; i < len(prefix); i++ {
			if prefix[i] == '-' {
				set[prefix[:i+1]+".service.d"] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// dropInFinding reads every drop-in file that applies to a unit and reports
// whether one assigns ExecStart=. A drop-in is "parsed after the main unit
// file itself" (systemd.unit(5)), so one that assigns it can change the
// program, and the unit file alone no longer says what runs.
func (s *serviceDirScan) dropInFinding(name string) string {
	if s.denied {
		return "drop_in_not_read"
	}
	notRead, sets := false, false
	for _, dirName := range s.dropInDirNames(name) {
		for _, dir := range s.dropInDirs[dirName] {
			entries, err := os.ReadDir(dir)
			if err != nil {
				notRead = true
				continue
			}
			for _, e := range entries {
				if !strings.HasSuffix(e.Name(), ".conf") {
					continue
				}
				content, err := readCapped(filepath.Join(dir, e.Name()))
				if err != nil {
					notRead = true
					continue
				}
				if assignsExecStart(string(content)) {
					sets = true
				}
			}
		}
	}
	switch {
	case notRead:
		return "drop_in_not_read"
	case sets:
		return "drop_in_sets_exec_start"
	}
	return ""
}

// assignsExecStart reports whether a drop-in assigns ExecStart= in any
// section. Any section, not only [Service], because erring wide here costs a
// "not determined" and never a wrong package.
func assignsExecStart(content string) bool {
	for _, raw := range logicalLines(content) {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if key, _, found := strings.Cut(line, "="); found && strings.TrimSpace(key) == "ExecStart" {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------- os-release

// readDistribution reads ID, VERSION_ID and VERSION_CODENAME. os-release(5):
// "Applications should check for the former, and exclusively use its data if
// it exists, and only fall back to /usr/lib/os-release if it is missing."
// readKeyValueFile keeps the last of a repeated key, which is the reading the
// same page asks for.
func readDistribution(root string) (*hostdoc.Distribution, hostdoc.Section) {
	values, verdict := readKeyValueFile(filepath.Join(root, "etc/os-release"))
	if verdict.Status == hostdoc.StatusNotPresent {
		values, verdict = readKeyValueFile(filepath.Join(root, "usr/lib/os-release"))
	}
	if verdict.Status != hostdoc.StatusCollected {
		return nil, verdict
	}
	keep := func(v string) string {
		if hostdoc.DistributionValue(v) {
			return v
		}
		return ""
	}
	return &hostdoc.Distribution{
		ID:              keep(values["ID"]),
		VersionID:       keep(values["VERSION_ID"]),
		VersionCodename: keep(values["VERSION_CODENAME"]),
	}, verdict
}

// ------------------------------------------------------------- dpkg's files

// mergedUsr reports which of mergedUsrDirs are links into /usr on this host.
func mergedUsr(root string) map[string]bool {
	out := map[string]bool{}
	for _, d := range mergedUsrDirs {
		dest, err := os.Readlink(filepath.Join(root, d))
		if err != nil {
			continue
		}
		dest = filepath.Clean(dest)
		if dest == "usr/"+d || dest == "/usr/"+d {
			out[d] = true
		}
	}
	return out
}

// spellings is a path under every name it has on this host: itself, and on a
// merged-/usr host the same file under the other top-level directory.
func spellings(path string, merged map[string]bool) []string {
	if path == "" {
		return nil
	}
	out := []string{path}
	for _, d := range mergedUsrDirs {
		if !merged[d] {
			continue
		}
		if rest, ok := strings.CutPrefix(path, "/usr/"+d+"/"); ok {
			out = append(out, "/"+d+"/"+rest)
		}
		if rest, ok := strings.CutPrefix(path, "/"+d+"/"); ok {
			out = append(out, "/usr/"+d+"/"+rest)
		}
	}
	return out
}

// listFileLists names the *.list files in dpkg's info directory, one per
// installed package: "name.list", or "name:arch.list" for a package installed
// for more than one architecture (measured on all four releases above).
func listFileLists(infoDir string) ([]string, hostdoc.Section) {
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		return nil, fileVerdict(err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".list") {
			out = append(out, e.Name())
		}
	}
	return out, hostdoc.Section{Status: hostdoc.StatusCollected}
}

// listOwner is one package whose file list names a wanted path.
type listOwner struct {
	name string
	// arch is the qualifier from "name:arch.list", empty for "name.list".
	arch string
}

// scanFileLists reads every file list once and returns, for each wanted path,
// the packages whose list names it. One line is one path, as dpkg wrote it.
func scanFileLists(infoDir string, lists []string, wanted map[string]bool) (map[string][]listOwner, hostdoc.Section) {
	owners := map[string][]listOwner{}
	verdict := hostdoc.Section{Status: hostdoc.StatusCollected}
	if len(wanted) == 0 {
		// Nothing to look up, so nothing is read. The directory listing
		// already showed the database is there.
		return owners, verdict
	}
	total := 0
	for _, list := range lists {
		name, arch, _ := strings.Cut(strings.TrimSuffix(list, ".list"), ":")
		n, err := scanOneList(filepath.Join(infoDir, list), func(line string) {
			if wanted[line] {
				owners[line] = append(owners[line], listOwner{name: name, arch: arch})
			}
		})
		total += n
		if err != nil {
			// A list that was in the listing and is gone when opened was
			// removed while this ran, and its owners went with it. It
			// still reads as a failed read, not as an absence, so this run
			// lists no units rather than an owner list that may be short.
			v := fileVerdict(err)
			if v.Status == hostdoc.StatusNotPresent {
				v = hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
			}
			verdict = worseVerdict(verdict, v)
			continue
		}
		if total > maxListTotalBytes {
			return owners, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
		}
	}
	return owners, verdict
}

// errPastCap marks a file refused for its size, which fileVerdict reads as a
// read error.
var errPastCap = errors.New("file is larger than its cap")

// countingReader counts the bytes read through it, so a capped read can tell
// a file that ended at its cap from one that went on past it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// scanOneList calls line for every line of one file list and returns how many
// bytes it read. A line longer than 64 KiB is not a path, PATH_MAX being 4096
// (see hostdoc.MaxCgroupPathLen), so it fails the read.
func scanOneList(path string, line func(string)) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	cr := &countingReader{r: io.LimitReader(f, int64(maxListBytes)+1)}
	sc := bufio.NewScanner(cr)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for sc.Scan() {
		line(sc.Text())
	}
	if err := sc.Err(); err != nil {
		return cr.n, err
	}
	if cr.n > maxListBytes {
		return cr.n, errPastCap
	}
	return cr.n, nil
}

// readDiversions reads the paths dpkg-divert has moved aside. The file is
// three lines per diversion, the path, where it was moved to, and the package
// that diverted it or ":" for the administrator (measured on all four
// releases above, with dpkg-divert run both ways). Only the first line of
// each three matters here: the file now at that path is not necessarily the
// one its owner shipped.
func readDiversions(path string) (map[string]bool, hostdoc.Section) {
	content, err := readCapped(path)
	if err != nil {
		return nil, fileVerdict(err)
	}
	out := map[string]bool{}
	text := strings.TrimSuffix(string(content), "\n")
	if text == "" {
		return out, hostdoc.Section{Status: hostdoc.StatusCollected}
	}
	lines := strings.Split(text, "\n")
	if len(lines)%3 != 0 {
		return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	}
	for i := 0; i < len(lines); i += 3 {
		out[lines[i]] = true
	}
	return out, hostdoc.Section{Status: hostdoc.StatusCollected}
}

func ownerNames(owners map[string][]listOwner) map[string]bool {
	out := map[string]bool{}
	for _, list := range owners {
		for _, o := range list {
			out[o.name] = true
		}
	}
	return out
}

// stanza is the five fields of one status file stanza this collector reads.
type stanza struct {
	pkg, status, arch, version, source string
}

// readStatus reads the stanzas of the named packages from dpkg's status file.
// Stanzas are separated by a blank line, a field is "Name: value", and a line
// starting with a space or a tab continues the field before it, which none of
// the five fields read here uses. The field names are matched as dpkg writes
// them, which is how they read in every status file measured.
func readStatus(path string, names map[string]bool) (map[string][]stanza, hostdoc.Section) {
	if len(names) == 0 {
		// No path had an owner, so no stanza is needed.
		return map[string][]stanza{}, openVerdict(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fileVerdict(err)
	}
	defer f.Close()
	out := map[string][]stanza{}
	cr := &countingReader{r: io.LimitReader(f, int64(maxStatusBytes)+1)}
	sc := bufio.NewScanner(cr)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	cur := stanza{}
	flush := func() {
		if cur.pkg != "" && names[cur.pkg] {
			out[cur.pkg] = append(out[cur.pkg], cur)
		}
		cur = stanza{}
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Package":
			cur.pkg = value
		case "Status":
			cur.status = value
		case "Architecture":
			cur.arch = value
		case "Version":
			cur.version = value
		case "Source":
			cur.source = value
		}
	}
	if err := sc.Err(); err != nil || cr.n > maxStatusBytes {
		return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	}
	flush()
	return out, hostdoc.Section{Status: hostdoc.StatusCollected}
}

// ------------------------------------------------- from evidence to entries

// ownerDB is everything read from dpkg, put together for the entries.
type ownerDB struct {
	owners   map[string][]listOwner
	stanzas  map[string][]stanza
	diverted map[string]bool
	merged   map[string]bool
}

func (db ownerDB) unitPackage(ev unitEvidence) hostdoc.UnitPackage {
	u := hostdoc.UnitPackage{Unit: ev.name, Finding: ev.finding, ProgramKind: ev.kind}
	// A cut or a malformed field matters only while every step so far had
	// an answer: an entry that already names no program says so first.
	note := func(f string) {
		if u.Finding == "complete" {
			u.Finding = f
		}
	}
	u.UnitFile = db.ownedPath(ev.unitFile, note)
	u.Program = db.ownedPath(ev.program, note)
	u.ProgramTarget = db.ownedPath(ev.target, note)
	return u
}

// ownedPath puts the owners and the diversion beside one path.
func (db ownerDB) ownedPath(path string, note func(string)) *hostdoc.OwnedPath {
	if path == "" {
		return nil
	}
	op := &hostdoc.OwnedPath{Path: sanitizeName(path)}
	seen := map[listOwner]bool{}
	var found []listOwner
	for _, sp := range spellings(path, db.merged) {
		if db.diverted[sp] {
			op.Diverted = true
		}
		for _, o := range db.owners[sp] {
			if !seen[o] {
				seen[o] = true
				found = append(found, o)
			}
		}
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].name != found[j].name {
			return found[i].name < found[j].name
		}
		return found[i].arch < found[j].arch
	})
	for _, o := range found {
		p, ok := db.packageOf(o, note)
		if !ok {
			continue
		}
		if len(op.Owners) == hostdoc.MaxOwnersPerPath {
			note("over_cap")
			break
		}
		op.Owners = append(op.Owners, p)
	}
	return op
}

// packageOf builds one owner from its file list's name and its stanza. Each
// field is checked against what the document will carry, and one that does
// not fit is left out with the reason noted, never cleaned into a value the
// host did not write.
func (db ownerDB) packageOf(o listOwner, note func(string)) (hostdoc.Package, bool) {
	field := func(v string) string {
		switch {
		case v == "":
			return ""
		case len(v) > hostdoc.MaxPackageFieldLen:
			note("over_cap")
			return ""
		case !hostdoc.PackageText(v):
			note("record_malformed")
			return ""
		}
		return v
	}
	p := hostdoc.Package{Name: field(o.name)}
	if p.Name == "" {
		return p, false
	}
	st, ok := pickStanza(db.stanzas[o.name], o.arch)
	if !ok {
		return p, true
	}
	p.Architecture = field(st.arch)
	p.Version = field(st.version)
	p.Installed = installedStatus(st.status)
	name, version, malformed := splitSource(st.source)
	if malformed {
		note("record_malformed")
	}
	p.Source = field(name)
	if p.Source != "" {
		p.SourceVersion = field(version)
	}
	return p, true
}

// pickStanza finds the stanza a file list belongs to. "name:arch.list"
// belongs to the stanza of that name and architecture. "name.list" belongs to
// the only stanza of that name, and to none when there are several, because
// which one it is would be a guess.
func pickStanza(list []stanza, arch string) (stanza, bool) {
	if arch != "" {
		for _, st := range list {
			if st.arch == arch {
				return st, true
			}
		}
		return stanza{}, false
	}
	if len(list) == 1 {
		return list[0], true
	}
	return stanza{}, false
}

// installedStatus reads a Status field, "install ok installed" on a package
// in use. The flag must be ok and the state installed, see
// hostdoc.Package.Installed for the words dpkg(1) gives them.
func installedStatus(status string) bool {
	words := strings.Fields(status)
	return len(words) == 3 && words[1] == "ok" && words[2] == "installed"
}

// splitSource splits a Source field, "util-linux (2.39.3-9ubuntu6.6)", into
// the name and the version in parentheses (deb-control(5), dpkg 1.21.22, read
// 2026-10-03). It reports malformed when something follows the name that is
// not one parenthesised version.
func splitSource(value string) (name, version string, malformed bool) {
	name, rest, found := strings.Cut(strings.TrimSpace(value), " ")
	if !found {
		return name, "", false
	}
	rest = strings.TrimSpace(rest)
	inner, ok := strings.CutPrefix(rest, "(")
	if !ok {
		return name, "", true
	}
	inner, ok = strings.CutSuffix(inner, ")")
	if !ok || strings.TrimSpace(inner) == "" {
		return name, "", true
	}
	return name, strings.TrimSpace(inner), false
}
