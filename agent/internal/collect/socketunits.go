// This file is the socket-unit collector: what systemd's *.socket unit files
// declare, read from the unit files themselves. Never over DBus, never by
// executing systemctl, because the agent executes nothing (PRODUCT.md 4e).
// The model for it is firewalld.go, which reads a configuration the same way.
//
// Why it exists: for a socket-activated service the manager owns the listening
// socket, so the sockets collector attributes port 22 to "systemd" pid 1, which
// names nothing (RECORD.md 4.64), and an unprivileged agent gets no process
// name at all (RECORD.md 4.72). The unit file names the service, and it is
// world readable, so this costs no privilege.
//
// What it must never do: say a port is open. A unit file is a declaration. The
// file existing is one fact, a symlink in a .wants directory is a second, the
// unit being active is a third, and something listening is a fourth. Only the
// first two are file reads, so those are the only two reported here. Joining a
// declared port to a measured listening socket belongs to the control plane,
// exactly like firewalld's configured intent against the kernel's ruleset.
package collect

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// socketUnitDirs are the unit directories this collector reads, in systemd's
// own precedence order: "Unit files found in directories listed earlier
// override files with the same name in directories lower in the list"
// (systemd.unit(5), UNIT FILE LOAD PATH, table 1, read on systemd 255).
//
// The three generator directories are read, at their real positions in that
// table: generator.early outranks /etc/systemd/system, generator sits between
// /run/systemd/system and /usr/local/lib/systemd/system, and generator.late
// sits below /usr/lib/systemd/system. They are regenerated at every boot,
// which was the reason an earlier version skipped them, and that reason does
// not hold: a generated unit is loaded and enabled right now. An AlmaLinux 10
// server had /run/systemd/generator/sshd-unix-local.socket (read 2026-08-21), and
// systemd-ssh-generator(8) writes TCP listeners into the same directory from
// the ssh.listen credential.
//
// Still not read, and named so their absence is a stated fact rather than a
// silence: /etc/systemd/system.control, /run/systemd/system.control and
// /run/systemd/transient, which are the manager's own DBus and transient
// state, and /etc/systemd/system.attached and /run/systemd/system.attached,
// which hold portable service units. The last two are absent from
// systemd.unit(5)'s table on both 255 and 257 and were found with
// `systemd-analyze unit-paths` on a live host.
var socketUnitDirs = []struct {
	// Key is the per-source verdict key, one of hostdoc.SocketUnitSources.
	Key string
	// Rel is the directory relative to the collector's root.
	Rel string
	// Origin is one of hostdoc.SocketUnitOrigins. The manual's table calls
	// both /etc/systemd/system and /usr/local/lib/systemd/system
	// administrator directories, which is why two entries say admin.
	Origin string
}{
	{"run_systemd_generator_early", "run/systemd/generator.early", "generator"},
	{"etc_systemd_system", "etc/systemd/system", "admin"},
	{"run_systemd_system", "run/systemd/system", "runtime"},
	{"run_systemd_generator", "run/systemd/generator", "generator"},
	{"usr_local_lib_systemd_system", "usr/local/lib/systemd/system", "admin"},
	{"usr_lib_systemd_system", "usr/lib/systemd/system", "vendor"},
	{"run_systemd_generator_late", "run/systemd/generator.late", "generator"},
}

// CollectSocketUnits reads every *.socket unit file under root (normally "/"),
// one verdict per directory. Units are reported in load-path order and a unit
// present in two directories is reported twice, with its origin and its path,
// because resolving the override is a conclusion and conclusions belong to the
// control plane. That is firewalld.go's posture for a zone file in /etc
// shadowing the vendor copy, and the same reasoning applies here.
func CollectSocketUnits(root string) *hostdoc.SocketUnitsSection {
	sec := &hostdoc.SocketUnitsSection{Sources: map[string]hostdoc.Section{}}
	scan := scanUnitDirs(root)
	// Reported once, because they apply to every unit. Sorted so two runs
	// over one host produce identical output.
	sec.TypeDropIns = append([]string(nil), scan.typeDropIns...)
	sort.Strings(sec.TypeDropIns)

	// Which unit names have a file of their own. An enable link naming
	// something absent from this set is either a dangling link or a template
	// instance, and the two are told apart further down.
	haveFile := map[string]bool{}
	for _, c := range scan.files {
		haveFile[c.name] = true
	}

	for _, c := range scan.files {
		unit, denied := readSocketUnit(c, dropInsFor(c.name, scan), len(scan.typeDropIns) > 0, "")
		// The links are sorted so two runs over one host agree byte for byte,
		// the same reason every other list in this package is sorted.
		links := scan.links[unit.Name]
		sort.Strings(links)
		unit.EnableLinks = links
		sec.Units = append(sec.Units, unit)
		if denied {
			// A file we were not allowed to open comes back with Parsed
			// false, which is the same signal a malformed file gets. Without
			// this the directory would read collected and nobody could tell
			// "this unit file is broken" from "we were not allowed to look",
			// which is the shape RECORD.md 4.17 forbids.
			scan.verdicts[c.dir] = worseVerdict(scan.verdicts[c.dir], hostdoc.Section{
				Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission})
		}
	}
	// Enabled template instances. systemd loads inst@7006.socket from the
	// template inst@.socket, so the instance has no file of its own and the
	// scan above never sees it. Dropping it lost a listening port: a
	// sockets.target.wants link over a template declaring ListenStream=%i is
	// a real, enabled port and it was absent from the document entirely.
	//
	// Only a link whose template actually exists becomes an entry. A link
	// naming nothing at all is a dangling link, which systemd.unit(5) says is
	// expected, and inventing a unit for one would be worse than dropping it.
	var instanceNames []string
	for name := range scan.links {
		if haveFile[name] {
			continue
		}
		if _, _, ok := instanceOf(name); ok {
			instanceNames = append(instanceNames, name)
		}
	}
	sort.Strings(instanceNames)
	for _, name := range instanceNames {
		template, instance, _ := instanceOf(name)
		var from *socketUnitCandidate
		for i := range scan.files {
			if scan.files[i].name == template {
				from = &scan.files[i]
				break
			}
		}
		if from == nil {
			continue
		}
		cand := *from
		cand.name = name
		unit, _ := readSocketUnit(cand, dropInsFor(name, scan), len(scan.typeDropIns) > 0, instance)
		links := scan.links[name]
		sort.Strings(links)
		unit.EnableLinks = links
		sec.Units = append(sec.Units, unit)
	}

	for i, d := range socketUnitDirs {
		sec.Sources[d.Key] = scan.verdicts[i]
	}
	sec.Section = aggregateSources(sec.Sources)
	return sec
}

// socketUnitCandidate is one *.socket file found during the directory scan.
type socketUnitCandidate struct {
	// dir indexes socketUnitDirs.
	dir int
	// name is the unit name, which is the file name, sanitized.
	name string
	// path is the real path to open, unsanitized.
	path string
	// reported is the path as the host knows it, absolute and sanitized.
	reported string
	// root is the collector's file-system root, needed to tell whether a
	// symlink still points inside the unit directories.
	root string
}

// socketUnitScan is what one pass over the unit directories found. Links and
// drop-ins are keyed by unit name rather than by directory, because a link in
// /etc/systemd/system/sockets.target.wants names a unit file that usually
// lives in /usr/lib/systemd/system.
type socketUnitScan struct {
	verdicts []hostdoc.Section
	files    []socketUnitCandidate
	// links maps a unit name to the .wants and .requires symlinks found for
	// it. The match is on the link's name, because that is the unit name
	// systemd resolves, and the manual notes the link may even dangle.
	links map[string][]string
	// dropIns maps a unit name to the *.conf files in its own <unit>.d
	// directory.
	dropIns map[string][]string
	// prefixDropIns maps a dashed name prefix ("foo-bar-") to the *.conf
	// files in a foo-bar-.socket.d directory, which applies to every socket
	// unit whose name starts with that prefix (systemd.unit(5)).
	prefixDropIns map[string][]string
	// typeDropIns are the *.conf files in a socket.d directory, the top-level
	// drop-in that applies to every socket unit on the system.
	typeDropIns []string
}

// scanUnitDirs lists each unit directory once and sorts what it finds into
// unit files, enablement links and drop-in files.
func scanUnitDirs(root string) *socketUnitScan {
	s := &socketUnitScan{
		verdicts:      make([]hostdoc.Section, len(socketUnitDirs)),
		links:         map[string][]string{},
		dropIns:       map[string][]string{},
		prefixDropIns: map[string][]string{},
	}
	for i, d := range socketUnitDirs {
		dir := filepath.Join(root, d.Rel)
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Most hosts have no /usr/local/lib/systemd/system, and an absent
			// directory is a measured answer.
			s.verdicts[i] = fileVerdict(err)
			continue
		}
		s.verdicts[i] = hostdoc.Section{Status: hostdoc.StatusCollected}
		denied := false
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() {
				if !s.readUnitSubdir(dir, d.Rel, name) {
					denied = true
				}
				continue
			}
			// Only an exact .socket suffix is a unit file. A symlink is kept:
			// /etc/systemd/system/foo.socket is often a link to the vendor
			// file, and a link to /dev/null is how a unit is masked.
			if !strings.HasSuffix(name, ".socket") {
				continue
			}
			s.files = append(s.files, socketUnitCandidate{
				dir:      i,
				root:     root,
				name:     sanitizeName(name),
				path:     filepath.Join(dir, name),
				reported: sanitizeName("/" + filepath.Join(d.Rel, name)),
			})
		}
		if denied {
			s.verdicts[i] = worseVerdict(s.verdicts[i], hostdoc.Section{
				Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission})
		}
	}
	// os.ReadDir returns entries sorted by file name, and the directories are
	// walked in a fixed order, so s.files is already deterministic.
	return s
}

// readUnitSubdir records what one subdirectory of a unit directory holds and
// reports false when it could not be read for lack of permission. Three kinds
// matter, all from systemd.unit(5):
//
//   - <target>.wants and <target>.requires hold the symlinks that enablement
//     is made of
//   - <unit>.socket.d holds that unit's drop-in *.conf files, and in the
//     dashed form foo-.socket.d it applies to every socket unit whose name
//     starts with "foo-"
//   - socket.d is the top-level drop-in for every socket unit on the system
func (s *socketUnitScan) readUnitSubdir(dir, rel, name string) bool {
	kind := ""
	switch {
	case strings.HasSuffix(name, ".wants"), strings.HasSuffix(name, ".requires"):
		kind = "links"
	case name == "socket.d":
		kind = "type_dropin"
	case strings.HasSuffix(name, ".socket.d"):
		kind = "dropin"
	default:
		return true
	}
	entries, err := os.ReadDir(filepath.Join(dir, name))
	if err != nil {
		return !os.IsPermission(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		child := sanitizeName("/" + filepath.Join(rel, name, e.Name()))
		switch kind {
		case "links":
			if strings.HasSuffix(e.Name(), ".socket") {
				unit := sanitizeName(e.Name())
				s.links[unit] = append(s.links[unit], child)
			}
		case "type_dropin":
			if strings.HasSuffix(e.Name(), ".conf") {
				s.typeDropIns = append(s.typeDropIns, child)
			}
		case "dropin":
			if !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			unit := strings.TrimSuffix(name, ".d")
			if prefix, ok := strings.CutSuffix(unit, "-.socket"); ok {
				s.prefixDropIns[prefix+"-"] = append(s.prefixDropIns[prefix+"-"], child)
				continue
			}
			s.dropIns[sanitizeName(unit)] = append(s.dropIns[sanitizeName(unit)], child)
		}
	}
	return true
}

// dropInsFor collects every drop-in file that applies to one unit name: its
// own directory, every dashed-prefix directory it falls under, and the
// top-level socket.d. Drop-ins for a unit's aliases are not resolved, because
// that needs the [Install] Alias= graph and the symlinks that implement it.
func dropInsFor(name string, s *socketUnitScan) []string {
	var out []string
	out = append(out, s.dropIns[name]...)
	for prefix, paths := range s.prefixDropIns {
		if strings.HasPrefix(name, prefix) {
			out = append(out, paths...)
		}
	}
	// s.typeDropIns is deliberately not appended. Those apply to every
	// socket unit, so they are reported once on the section instead. See
	// hostdoc.SocketUnitsSection.TypeDropIns for the measurements that
	// forced it. The unit is still marked, below.
	sort.Strings(out)
	return out
}

// aliasTarget reports the unit a .socket file links to, when it links to
// another unit rather than to /dev/null. Deliberately shallow: it reads the
// link once and looks at the name it points at, because resolving a chain
// across directories is the kind of cleverness that gets a port wrong.
func aliasTarget(path, name string) (string, bool) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", false
	}
	dest, err := os.Readlink(path)
	if err != nil {
		return "", false
	}
	base := sanitizeName(filepath.Base(dest))
	if !strings.HasSuffix(base, ".socket") || base == name {
		return "", false
	}
	return base, true
}

// maxDescription is how much of a unit's Description= the agent will put on
// the wire. The host writes that text, so its length is the host's choice, and
// one file with a megabyte in it should not become a megabyte of report. 1 KiB
// is far longer than any real description: the longest on either fleet host is
// under 80 bytes.
//
// It is cut rather than dropped, because the first bytes are the useful ones,
// and the unit says description_truncated so nobody reads a cut string as the
// whole one.
const maxDescription = 1024

func capDescription(d string) (string, bool) {
	if len(d) <= maxDescription {
		return d, false
	}
	return d[:maxDescription], true
}

// expandInstance substitutes "%i" in a listener value with the instance name
// and reparses it. Only "%i" and only when the instance is known.
//
// This is a substitution rather than a guess. The instance name is a fact read
// off the enable link's own filename, and systemd.unit(5) defines %i as that
// name. It is the same kind of step as reading foo.socket to mean foo.service,
// which this collector already does and labels.
//
// Every other specifier is left alone and keeps kind "specifier". %I needs the
// unescaping rules, %H and %b are runtime state no file carries, and inventing
// any of them would be exactly what the bare-port rule exists to prevent.
func expandInstance(listen []hostdoc.SocketUnitListen, instance string) []hostdoc.SocketUnitListen {
	if instance == "" {
		return listen
	}
	out := make([]hostdoc.SocketUnitListen, 0, len(listen))
	for _, l := range listen {
		if l.Kind == "specifier" && strings.Contains(l.Value, "%i") &&
			!strings.Contains(strings.ReplaceAll(l.Value, "%i", ""), "%") {
			expanded := strings.ReplaceAll(l.Value, "%i", instance)
			out = append(out, parseListenValue(l.Directive, expanded))
			continue
		}
		out = append(out, l)
	}
	return out
}

// instanceOf splits "inst@7006.socket" into its template name and instance.
// A unit with an empty instance, "inst@.socket", is the template itself.
func instanceOf(name string) (template, instance string, ok bool) {
	base, found := strings.CutSuffix(name, ".socket")
	if !found {
		return "", "", false
	}
	prefix, inst, found := strings.Cut(base, "@")
	if !found || inst == "" {
		return "", "", false
	}
	return prefix + "@.socket", inst, true
}

// incompleteReasons builds the typed list that warns a reader the address list
// may not be what systemd computed. The order is fixed so two runs over one
// host produce identical output.
func incompleteReasons(dropIns []string, anyTypeDropIns bool,
	undocumentedReset, repeated, descriptionCut bool) []string {
	var out []string
	// Drop-ins are detected and reported, never merged. Merging them
	// correctly means the name-specific, dashed-prefix and top-level
	// directories across three trees, in lexicographic order across
	// directories, plus the list-reset rule, and getting that subtly wrong
	// would produce a confident wrong port list. Saying "there are drop-ins
	// here and this list does not include them" cannot be wrong.
	// anyTypeDropIns is passed separately because the top-level drop-ins
	// live on the section now, not in this list. They still apply to this
	// unit, so the unit still has to say its address list may be partial.
	if len(dropIns) > 0 || anyTypeDropIns {
		out = append(out, "drop_ins")
	}
	if undocumentedReset {
		out = append(out, "listen_reset_undocumented")
	}
	if repeated {
		out = append(out, "repeated_directive")
	}
	if descriptionCut {
		out = append(out, "description_truncated")
	}
	return out
}

// readSocketUnit reads and parses one unit file. dropIns are the drop-in files
// already found for this unit name, which belong to the entry whether or not
// the unit file itself could be read. The second return value is true when the
// read was denied, which the caller carries into the directory's verdict.
func readSocketUnit(c socketUnitCandidate, dropIns []string,
	anyTypeDropIns bool, instance string) (hostdoc.SocketUnit, bool) {
	u := hostdoc.SocketUnit{
		Name:   c.name,
		File:   c.reported,
		Origin: socketUnitDirs[c.dir].Origin,
		// Empty unless this entry is a template instance made from an
		// enable link, in which case File points at the template.
		Instance: instance,
		// The directory key, so a reader can rank two copies of one unit.
		// Origin cannot: /etc/systemd/system and /usr/local/lib/systemd/system
		// are both "admin".
		Source:  socketUnitDirs[c.dir].Key,
		DropIns: dropIns,
		// A template file is the pattern instances are made from and is not
		// itself a listener (systemd.unit(5)): its addresses can carry an
		// unresolved "%i", and the instances exist only in the manager's
		// runtime state, which is not a file. It is reported anyway, because
		// "this host ships a socket template declaring these addresses" is
		// evidence, and every address value carrying a specifier is reported
		// as a specifier rather than interpreted.
		Template: strings.HasSuffix(c.name, "@.socket"),
	}
	u.Incomplete = incompleteReasons(dropIns, anyTypeDropIns, false, false, false)
	// Masking, first, because a masked unit is not loaded at all: "If a unit
	// file is empty (i.e. has the file size 0) or is symlinked to /dev/null,
	// its configuration will not be loaded and it appears with a load state
	// of masked" (systemd.unit(5)).
	if unitSymlinkRefused(c.root, c.path) {
		// Present and deliberately not read. Parsed stays false, which is the
		// same signal a malformed or unreadable file gets, and the reason says
		// which of those it is.
		u.Incomplete = append(u.Incomplete, "symlink_outside_unit_directories")
		return u, false
	}
	if masked, err := isMaskedUnit(c.path); err != nil {
		return u, os.IsPermission(err)
	} else if masked {
		u.Masked = true
		return u, false
	}
	// A link to another unit file is an alias: systemd reads it as a second
	// name for one unit. Reporting its addresses again would count one real
	// port twice, and implying a service from the link's own name invents one.
	if target, ok := aliasTarget(c.path, c.name); ok {
		u.AliasOf = target
		return u, false
	}
	content, err := readCapped(c.path)
	if err != nil {
		// Parsed stays false: the file is there and we do not know what it
		// says. A file past the cap lands here too, refused rather than
		// truncated, for the reason readCapped documents.
		return u, os.IsPermission(err)
	}
	body, ok := parseSocketUnit(string(content))
	if !ok {
		return u, false
	}
	u.Parsed = true
	u.SocketSection = body.hasSocket
	var descriptionCut bool
	u.Description, descriptionCut = capDescription(body.description)
	u.Listen = expandInstance(body.listen, instance)
	u.ListenReset = body.listenReset
	u.Accept = body.accept
	u.BindIPv6Only = body.bindIPv6Only
	u.ServiceUnit, u.ServiceSource = serviceUnitFor(c.name, body.service, body.accept,
		body.acceptSet, u.Listen)
	u.Incomplete = incompleteReasons(dropIns, anyTypeDropIns, body.undocumentedReset,
		body.repeated, descriptionCut)
	return u, false
}

// isMaskedUnit reports whether the path is a masked unit: a zero-length file,
// or a symlink to /dev/null (systemd.unit(5)). A symlink chain that reaches
// /dev/null through another link is not detected, and lands as an unparsed
// entry rather than as a masked one.
func isMaskedUnit(path string) (bool, error) {
	if target, err := os.Readlink(path); err == nil {
		if filepath.Clean(target) == "/dev/null" {
			return true, nil
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		// A directory named foo.socket, or a device node. Not a unit file we
		// will read, and not something to claim anything about.
		return false, os.ErrInvalid
	}
	return info.Size() == 0, nil
}

// unitSymlinkRefused reports whether a unit file is a symlink the collector
// will not follow, so the caller opens nothing and marks the unit instead.
//
// systemd uses symlinks under unit directories for three honest things: /dev/null
// to mask, another unit file to alias, and a unit file in another unit directory
// to enable. All three resolve to /dev/null or to a real file inside the unit
// directories.
//
// The whole chain is resolved, not one hop. An earlier version read a single
// link with os.Readlink, so a two-hop chain whose first link landed back inside
// a unit directory passed the check while its second link pointed at any file on
// the host. os.Open in readCapped follows every hop, so the guard has to as
// well, or it guards a shorter path than the one that gets opened. A link to any
// INI-shaped file copied that file's Description= into the document and posted it
// to the control plane. It needs write access to a unit directory, which normally
// means root already, so this is a smaller hole than it sounds and it is still
// not one to leave open: the agent should not be a way to read a file its own
// reader did not choose.
//
// A chain that does not resolve, a loop or a broken link, is refused too. There
// is no real file at the end to prove is in bounds, and letting a later os.Open
// chase the same chain is what this check exists to stop. It carries the same
// marker as a link out of the tree, because in both cases a symlinked unit file
// was refused rather than read, which is the fact a reader needs.
//
// root is the collector's file-system root, so a fixture tree checks the same
// way "/" does. Both the resolved target and each unit directory are passed
// through EvalSymlinks before they are compared, so a symlink in the root path
// itself, such as macOS /var to /private/var, does not read as an escape.
func unitSymlinkRefused(root, path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		// Not a symlink, so there is nothing to follow.
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		// A loop, a broken link, or a component that cannot be traversed. The
		// chain reaches no real file to bound-check, so it is refused.
		return true
	}
	if filepath.Clean(resolved) == "/dev/null" {
		// A mask link. isMaskedUnit reads it next.
		return false
	}
	for _, d := range socketUnitDirs {
		dir, err := filepath.EvalSymlinks(filepath.Join(root, d.Rel))
		if err != nil {
			// The directory is absent on this host, so nothing resolves into it.
			continue
		}
		if resolved == dir || strings.HasPrefix(resolved, dir+string(filepath.Separator)) {
			return false
		}
	}
	return true
}

// socketUnitBody is one parsed unit file.
type socketUnitBody struct {
	description string
	hasSocket   bool
	listen      []hostdoc.SocketUnitListen
	listenReset bool
	service     string
	accept      string
	acceptSet   bool

	bindIPv6Only string
	// undocumentedReset records an empty assignment to a Listen directive
	// whose reset behaviour the manual does not describe.
	undocumentedReset bool
	// repeated records a single-valued directive assigned more than once.
	repeated bool

	serviceSet     bool
	bindSet        bool
	descriptionSet bool
}

// parseSocketUnit parses one unit file's text. The syntax is systemd.syntax(7):
// sections in brackets, key=value entries with whitespace around "=" ignored,
// and blank lines or lines starting with "#" or ";" ignored.
//
// It returns false when the file has data lines and none of them parsed, the
// same posture readKeyValueFile takes: garbage must never read as an empty
// success. An empty file never reaches here, because a zero-length unit file is
// masked.
func parseSocketUnit(content string) (socketUnitBody, bool) {
	var b socketUnitBody
	section := ""
	dataLines, parsedLines := 0, 0
	for _, line := range logicalLines(content) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		dataLines++
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			parsedLines++
			section = trimmed[1 : len(trimmed)-1]
			if section == "Socket" {
				b.hasSocket = true
			}
			continue
		}
		key, value, found := strings.Cut(trimmed, "=")
		if !found {
			continue
		}
		parsedLines++
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// Directive names are matched with the spelling the manual documents,
		// and a section is only read where the manual puts it: Description is
		// a [Unit] option, the rest are [Socket] options.
		switch section {
		case "Unit":
			if key == "Description" {
				if b.descriptionSet {
					b.repeated = true
				}
				b.descriptionSet = true
				b.description = sanitizeName(value)
			}
		case "Socket":
			b.socketDirective(key, value)
		}
	}
	if dataLines > 0 && parsedLines == 0 {
		return socketUnitBody{}, false
	}
	return b, true
}

// socketDirective handles one key=value line inside [Socket].
func (b *socketUnitBody) socketDirective(key, value string) {
	switch key {
	case "ListenStream", "ListenDatagram":
		if value == "" {
			// "If the empty string is assigned to any of these options, the
			// list of addresses to listen on is reset, all prior uses of any
			// of these options will have no effect" (systemd.socket(5)). Any
			// of these options: one empty ListenStream= drops the
			// ListenDatagram= entries above it too.
			b.listen = nil
			b.listenReset = true
			return
		}
		b.listen = append(b.listen, parseListenValue(key, value))
	case "ListenSequentialPacket", "ListenFIFO", "ListenSpecial",
		"ListenNetlink", "ListenMessageQueue", "ListenUSBFunction":
		// None of these can be a TCP or UDP port, so none produces an address
		// or a family. They are still recorded, because a unit that declares
		// one of them is not a unit that declares nothing, and dropping them
		// made fifteen real units across the fleet read as empty.
		//
		// The reset matters more. "If the empty string is assigned to any of
		// these options, the list of addresses to listen on is reset, all
		// prior uses of any of these options will have no effect"
		// (systemd.socket(5)). **Any of these options** is all eight, so an
		// empty ListenFIFO= discards ListenStream= entries written above it.
		// Honouring it for only three of the eight meant reporting a port
		// systemd would never bind.
		if value == "" {
			b.listen = nil
			b.listenReset = true
			return
		}
		b.listen = append(b.listen, hostdoc.SocketUnitListen{
			Directive: key,
			Value:     value,
			// Not a port and not an internet address, so there is nothing
			// here to specify one. The kind says which directive it was, and
			// the absent Port and AddressFamily say we are claiming neither.
			Kind: "not_an_internet_socket",
		})
	case "Service":
		if b.serviceSet {
			b.repeated = true
		}
		b.serviceSet = true
		b.service = sanitizeName(value)
	case "Accept":
		if b.acceptSet {
			b.repeated = true
		}
		b.acceptSet = true
		b.accept = sanitizeName(value)
	case "BindIPv6Only":
		if b.bindSet {
			b.repeated = true
		}
		b.bindSet = true
		b.bindIPv6Only = sanitizeName(value)
	default:
		// The manual documents the reset for the three directives above and
		// says nothing about the other Listen* ones, so an empty assignment
		// to one of those is flagged rather than guessed at. The unit then
		// carries listen_reset_undocumented and its address list is not
		// presented as the whole answer.
		if value == "" && strings.HasPrefix(key, "Listen") {
			b.undocumentedReset = true
		}
	}
}

// logicalLines splits a unit file into logical lines, applying systemd's
// continuation rule: "Lines ending in a backslash are concatenated with the
// following line while reading and the backslash is replaced by a space
// character", and "When a comment line or lines follow a line ending with a
// backslash, the comment block is ignored, so the continued line is
// concatenated with whatever follows the comment block" (systemd.syntax(7)).
//
// C-style escapes are deliberately not processed anywhere in this collector,
// because values are reported verbatim. The cost is that a value ending in an
// escaped backslash is joined with the following line here, and comes out as a
// value this collector does not recognise rather than as a confident wrong
// port.
func logicalLines(content string) []string {
	var out []string
	var acc strings.Builder
	continuing := false
	for _, line := range strings.Split(content, "\n") {
		if continuing {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
				continue
			}
		}
		if rest, ok := strings.CutSuffix(line, "\\"); ok {
			acc.WriteString(rest)
			acc.WriteString(" ")
			continuing = true
			continue
		}
		if continuing {
			acc.WriteString(line)
			out = append(out, acc.String())
			acc.Reset()
			continuing = false
			continue
		}
		out = append(out, line)
	}
	if continuing {
		// A file whose last line ends in a backslash has nothing to join, so
		// what was accumulated is the final logical line.
		out = append(out, acc.String())
	}
	return out
}

// parseListenValue reads one ListenStream= or ListenDatagram= value into the
// document's shape. Every address form here is one systemd.socket(5) documents,
// and anything that matches none of them is reported as unknown rather than
// forced into one.
//
// The rule that matters most: a bare number "specifies a port and no address".
// The manual says it "is read as port number to listen on via IPv6", and that
// depending on BindIPv6Only= this "might result in the service being available
// via both IPv6 and IPv4 (default) or just via IPv6", where the default is the
// /proc/sys/net/ipv6/bindv6only sysctl. So the file does not say what address
// or family it ends up with, and neither does this function. It records the
// port, leaves the address empty, and leaves AddressSpecified false. The unit's
// BindIPv6Only= travels beside it so the control plane can see what the file
// said about that too.
func parseListenValue(directive, value string) hostdoc.SocketUnitListen {
	l := hostdoc.SocketUnitListen{
		Directive: directive,
		Value:     sanitizeName(value),
		Kind:      "unknown",
	}
	switch {
	case strings.HasPrefix(value, "/"):
		// "If the address starts with a slash, it is read as file system
		// socket in the AF_UNIX socket family."
		l.Kind = "unix_path"
	case strings.HasPrefix(value, "@"):
		// "If the address starts with an at symbol, it is read as abstract
		// namespace socket in the AF_UNIX family."
		l.Kind = "unix_abstract"
	case strings.HasPrefix(value, "vsock:"):
		// AF_VSOCK CID and port. A vsock port is not a TCP or UDP port, so
		// Port stays 0 and the value is carried verbatim.
		l.Kind = "vsock"
	case strings.HasPrefix(value, "["):
		return parseListenIPv6(l, value)
	case isAllDigits(value):
		if port, ok := parsePort(value); ok {
			l.Kind = "port_only"
			l.Port = port
		}
	case strings.Contains(value, "%"):
		// A specifier this collector does not expand, "%i" in a template
		// being the common one. Expanding it would need the instance name,
		// which is runtime state and not in any file.
		l.Kind = "specifier"
	default:
		return parseListenIPv4(l, value)
	}
	return l
}

// parseListenIPv6 reads the "[x]:y" form, with the optional "%dev" interface
// scope that may follow the port (systemd.socket(5)).
func parseListenIPv6(l hostdoc.SocketUnitListen, value string) hostdoc.SocketUnitListen {
	end := strings.Index(value, "]")
	if end < 0 {
		return l
	}
	addr := value[1:end]
	rest, ok := strings.CutPrefix(value[end+1:], ":")
	if !ok {
		return l
	}
	// The scope belongs to the address, not to the port, and is only useful
	// for a link-local address.
	if i := strings.Index(rest, "%"); i >= 0 {
		rest = rest[:i]
	}
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() != nil {
		return l
	}
	port, ok := parsePort(rest)
	if !ok {
		return l
	}
	l.Kind = "ipv6"
	l.Address = sanitizeName(addr)
	l.AddressSpecified = true
	// The family of the literal in the file, and nothing more. An IPv6
	// literal can still answer IPv4 traffic depending on BindIPv6Only=, so
	// this is not "v6 only".
	l.AddressFamily = "v6"
	l.Port = port
	return l
}

// parseListenIPv4 reads the "v.w.x.y:z" form (systemd.socket(5)).
func parseListenIPv4(l hostdoc.SocketUnitListen, value string) hostdoc.SocketUnitListen {
	host, portText, found := strings.Cut(value, ":")
	if !found {
		return l
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return l
	}
	port, ok := parsePort(portText)
	if !ok {
		return l
	}
	l.Kind = "ipv4"
	l.Address = sanitizeName(host)
	l.AddressSpecified = true
	l.AddressFamily = "v4"
	l.Port = port
	return l
}

// serviceUnitFor answers which service unit gets the socket, and says whether
// the file stated it or this collector applied a rule. Keeping those two apart
// is the point: one is evidence, the other is our reading of the manual.
//
// systemd.socket(5) on Service=: "It defaults to the service that bears the
// same name as the socket (with the suffix replaced)." And on the naming rules,
// which depend on Accept=, whose own default is no: "a socket file foo.socket
// needs a matching service foo.service if Accept=no is set. If Accept=yes is
// set, a service template foo@.service must exist from which services are
// instantiated for each incoming connection."
func serviceUnitFor(unitName, declared, accept string, acceptSet bool,
	listen []hostdoc.SocketUnitListen) (string, string) {
	if declared != "" {
		return declared, "declared"
	}
	base := strings.TrimSuffix(unitName, ".socket")
	accepts, known := systemdBool(accept)
	if acceptSet && !known {
		// The file assigns Accept= something that is not a documented
		// boolean, so which naming rule applies is not knowable from here.
		return "", "unknown"
	}
	if !acceptSet {
		// "Defaults to no" (systemd.socket(5)).
		accepts = false
	}
	if !accepts {
		return base + ".service", "implied"
	}
	if strings.HasSuffix(base, "@") {
		// A template socket with Accept=yes. The manual's rule produces the
		// template name for a plain socket, and what it produces for a
		// template socket is not stated, so this collector does not guess.
		return "", "unknown"
	}
	if !everyListenerCanAccept(listen) {
		// Accept=yes needs sockets that can accept a connection. When one
		// cannot, systemd does not fall back to the plain service, it refuses
		// the unit: "Unit configured for accepting sockets, but sockets are
		// non-accepting. Refusing." (systemd 257, systemd-analyze verify,
		// read 2026-08-21). One datagram port beside a perfectly good stream
		// port kills the whole unit.
		//
		// The manual is softer than the manager here. systemd.socket(5) says
		// Accept= "is ignored for datagram sockets and FIFOs", which would
		// imply the plain name. The manager refuses outright, so no service
		// is named at all and the reader is told the list is not the answer.
		return "", "unknown"
	}
	return base + "@.service", "implied"
}

// everyListenerCanAccept reports whether every recorded listener is one that
// can accept a connection. Accept=yes is only valid for SOCK_STREAM and
// SOCK_SEQPACKET (systemd.socket(5) on Accept=, and the manager's own refusal
// quoted in serviceUnitFor).
//
// A unit with no listener at all returns true: there is nothing here that
// cannot accept, and the separate question of whether systemd loads a socket
// unit with no listener is not this function's to answer.
func everyListenerCanAccept(listen []hostdoc.SocketUnitListen) bool {
	for _, l := range listen {
		switch l.Directive {
		case "ListenStream", "ListenSequentialPacket":
		default:
			return false
		}
	}
	return true
}

// systemdBool parses a boolean the way systemd.syntax(7) documents it: "For
// positive settings the strings 1, yes, true and on are equivalent. For
// negative settings, the strings 0, no, false and off are equivalent." Only
// those spellings are accepted, and the second return value is false for
// anything else, so an unparseable value is never read as a no.
func systemdBool(value string) (bool, bool) {
	switch value {
	case "1", "yes", "true", "on":
		return true, true
	case "0", "no", "false", "off":
		return false, true
	}
	return false, false
}

// isAllDigits reports whether s is one or more ASCII digits and nothing else.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// parsePort reads a TCP or UDP port. Digits only, and inside the range a port
// can actually take, so a value like "+22" or "70000" is not silently accepted
// as a port.
func parsePort(s string) (int, bool) {
	if !isAllDigits(s) {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}
