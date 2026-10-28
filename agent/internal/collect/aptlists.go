// This file is the apt lists reader: which versions this host's own package
// lists offer for each package behind a listening service, and from whose
// archive. It reads the files apt keeps and never runs apt or dpkg, because
// the agent executes nothing (PRODUCT.md 4e).
//
// It reports evidence and stops, like the package collector beside it. Which
// version is the newer one, and what follows from it, is the control plane's
// to work out (docs/SPEC-cve-check.md, section 8.1).
//
// Like packages.go it is in every build since 2026-10-12, and stood behind a
// build tag that no release was built with until then (docs/RECORD.md 4.385,
// docs/SPEC-packages-switch.md).
//
// **Nothing an archive's owner wrote leaves the host** (SI-8). An archive
// says who it is in its own Release file, and for an archive a company runs
// for itself those are that company's words. This reader holds them against
// a closed list of three (hostdoc.OfferArchives) and reports the one word.
// For every other archive it reports two yes or no facts and nothing else:
// no version, no field, no file name, no address.
//
// What was measured, on 2026-10-06 on six installs of Debian 12 and Ubuntu
// 24.04 and on 2026-10-07 on a server running Ubuntu 26.04 (docs/RECORD.md
// 4.418 and 4.430): the folder is 0755 root, each list 0644, plain text, and
// an unprivileged user read one. The files are named by the mirror they came
// from, so only an archive's own Release file says whose it is. The server
// held 17 lists, 97.6 MiB.
//
// And on 2026-10-09, with the apt of a Debian 12 install in a container, apt
// 2.6.1, on archives made on the machine for each case and on the lists it
// fetched from Debian's and Ubuntu's own archives. Three things in this file
// rest on it:
//
//   - A list is an archive's only when that archive's Release file names it
//     among its files (whoseLists). The start of a list's name does not say
//     so: apt kept the list of an archive with no Release file of its own
//     under the name of the archive whose folder it stood in, and said of it
//     no origin and no label. Every list fetched from Debian's and Ubuntu's
//     archives was named in its archive's InRelease by its plain path, like
//     "main/binary-arm64/Packages", under SHA256.
//   - A line is read as apt reads it (aptField): a field's name in any case,
//     and any run of blanks or none after the colon and after the value.
//   - A flag is yes for the values apt took as yes (aptYes).
package collect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// aptListsDir is where apt keeps the lists it fetched, relative to the
// collector's root. apt.conf(5) names it as Dir::State::lists.
const aptListsDir = "var/lib/apt/lists"

// The read caps. A list is refused rather than cut past its cap, for the
// reason readCapped gives: half a list read as the whole one would report a
// version as not offered. The largest list measured is under 80 MiB. They
// are variables only so the tests can lower them.
var (
	// maxAptListBytes bounds one list.
	maxAptListBytes = 512 << 20
	// maxAptListsTotalBytes bounds every list read in one run together.
	maxAptListsTotalBytes = 2 << 30
	// maxReleaseBytes bounds an archive's Release file. The largest read is
	// Ubuntu 24.04's, 255,850 bytes.
	maxReleaseBytes = 16 << 20
	// maxVersionsPerList is how many versions of one package one list may
	// hold. A distribution's list holds one. An archive that keeps every
	// version it ever published holds some hundreds.
	maxVersionsPerList = 4096
)

// openAptList opens one list, and openAptRelease one archive's Release file.
// They are variables so the tests can count how many of each a run opens.
var (
	openAptList    = os.Open
	openAptRelease = os.Open
)

// errListNotUnderstood marks a list, or an archive's Release file, that is
// not in the shape this reader knows. fileVerdict reads it as a read error.
var errListNotUnderstood = errors.New("apt list is not in a shape this reader knows")

// ------------------------------------------------ a line of apt's own files

// aptField splits one line of a list, or of a Release file, into a field's
// name and its value. It is the one place that says what a field is, so the
// two readers below cannot come to read a line differently.
//
// It reads a line as apt was measured to: what stands before the first colon
// is the name, and the value is the rest with the blanks before it and after
// it taken off. apt read "Package: x", "Package:x", "Package:  x", a tab in
// the space's place and a blank after the value as the same field, in a list
// and in a Release file alike.
//
// A name is printable ASCII with no blank in it. A line that gives no such
// name before a colon is not a field, and ok is false.
func aptField(line []byte) (name, value []byte, ok bool) {
	colon := bytes.IndexByte(line, ':')
	if colon <= 0 {
		return nil, nil, false
	}
	name = line[:colon]
	for _, c := range name {
		if c <= ' ' || c > '~' {
			return nil, nil, false
		}
	}
	return name, bytes.Trim(line[colon+1:], " \t\r\n"), true
}

// isField reports whether name is the field want, whatever case it is
// written in: apt read "package", "Package" and "PACKAGE" as one field. want
// is given in lower case.
func isField(name []byte, want string) bool {
	if len(name) != len(want) {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != want[i] {
			return false
		}
	}
	return true
}

// goesOn reports whether a line is the line before it going on: it starts
// with a blank.
func goesOn(line []byte) bool {
	return line[0] == ' ' || line[0] == '\t'
}

// aptYes are the values of an archive's flag that mean yes, in any case.
//
// It is what apt 2.6.1 was measured to accept on 2026-10-09, in a container,
// for NotAutomatic: an archive that gave one of these got the weight 1 from
// apt, where an archive with no flag got 500. Each word was tried in lower
// case, with a capital first letter and in upper case, and the two numbers
// as they stand here.
//
// What apt took as no, by giving the weight 500: no field at all, a field
// with no value, "no", "No", "NO", "false", "False", "off", "disable",
// "without" and "0". And these, of each of which it said "Unknown flag
// value": "2", "-1", "y", "maybe" and "yes please". They are no here too.
var aptYes = []string{"yes", "true", "on", "enable", "with", "1", "01"}

// aptSaysYes reports whether a flag's value is one apt takes as yes.
func aptSaysYes(value string) bool {
	for _, yes := range aptYes {
		if strings.EqualFold(value, yes) {
			return true
		}
	}
	return false
}

// compressedListSuffixes are the endings apt gives a list it keeps
// compressed (apt.conf(5), Acquire::CompressionTypes). Go's standard library
// reads two of them and not the rest, and no host read so far keeps its
// lists that way, so such a list is not read and the read is not complete.
var compressedListSuffixes = []string{".gz", ".bz2", ".xz", ".lz4", ".lzma", ".zst"}

// askedPackage is one package behind a listening service, as dpkg has it.
type askedPackage struct {
	name string
	// versions are the versions dpkg says are installed, one unless the
	// package is installed for two architectures.
	versions map[string]bool
	// archs are the architectures it is installed for.
	archs map[string]bool
}

// askedPackages lists every package that owns a unit file or a program in
// units, sorted by name.
func askedPackages(units []hostdoc.UnitPackage) []askedPackage {
	byName := map[string]*askedPackage{}
	for _, u := range units {
		for _, path := range []*hostdoc.OwnedPath{u.UnitFile, u.Program, u.ProgramTarget} {
			if path == nil {
				continue
			}
			for _, owner := range path.Owners {
				a := byName[owner.Name]
				if a == nil {
					a = &askedPackage{name: owner.Name, versions: map[string]bool{}, archs: map[string]bool{}}
					byName[owner.Name] = a
				}
				if owner.Installed && owner.Version != "" {
					a.versions[owner.Version] = true
				}
				if owner.Architecture != "" {
					a.archs[owner.Architecture] = true
				}
			}
		}
	}
	out := make([]askedPackage, 0, len(byName))
	for _, a := range byName {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// ------------------------------------------------------ what the agent keeps

// keptVersion is the shape of what is kept. Bytes that say another number
// are bytes this reader did not write.
const keptVersion = 1

// listedVersion is one stanza of a list, the three fields this reader keeps.
type listedVersion struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

// keptList is one list as it was read: its name in apt's folder, the size
// and the time it had, and what it holds of the packages asked for.
type keptList struct {
	Name    string          `json:"name"`
	Size    int64           `json:"size"`
	MtimeNs int64           `json:"mtime_ns"`
	Found   []listedVersion `json:"found"`
}

// keptLists is what one complete read leaves for the next run. The agent's
// process ends after each report, so its caller keeps these bytes in a file
// of the agent's own beside its state file, and they never leave the host.
type keptLists struct {
	KeptVersion int        `json:"kept_version"`
	Asked       []string   `json:"asked"`
	Lists       []keptList `json:"lists"`
}

// understoodKept returns what was kept, or nil when the bytes are not
// exactly what this reader writes.
//
// The bytes come off a disk, and whoever can write there can write into
// them. So they are believed only when decoding them and encoding them again
// gives the same bytes, which refuses a field this reader does not write,
// anything after the end, and any other spelling. And every name, version
// and architecture in them is held to the shape one out of a list must have,
// so nothing out of this file goes into a report that could not have come
// out of a list.
func understoodKept(kept []byte) *keptLists {
	if len(kept) == 0 {
		return nil
	}
	var k keptLists
	if err := json.Unmarshal(kept, &k); err != nil {
		return nil
	}
	if again, err := json.Marshal(k); err != nil || !bytes.Equal(again, kept) {
		return nil
	}
	if k.KeptVersion != keptVersion || !sortedUnique(k.Asked) {
		return nil
	}
	asked := map[string]bool{}
	for _, name := range k.Asked {
		if !hostdoc.PackageText(name) {
			return nil
		}
		asked[name] = true
	}
	for i, l := range k.Lists {
		if !isPlainList(l.Name) || strings.ContainsAny(l.Name, "/\x00") || l.Size < 0 {
			return nil
		}
		if i > 0 && k.Lists[i-1].Name >= l.Name {
			return nil
		}
		for _, v := range l.Found {
			if !asked[v.Name] || !hostdoc.PackageVersion(v.Version) || !hostdoc.PackageText(v.Architecture) {
				return nil
			}
		}
	}
	return &k
}

func sortedUnique(names []string) bool {
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			return false
		}
	}
	return true
}

// covers reports whether what was kept was read for every package asked for
// now. A package that was not asked for then is in no kept list, and the
// lists have to be read for it.
func (k *keptLists) covers(asked []askedPackage) bool {
	had := map[string]bool{}
	for _, name := range k.Asked {
		had[name] = true
	}
	for _, a := range asked {
		if !had[a.name] {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------- an archive

// aptArchive is what one archive is to this reader: one of the three words
// of hostdoc.OfferArchives or "" for any other, and its two flags.
type aptArchive struct {
	word                 string
	notAutomatic         bool
	butAutomaticUpgrades bool
}

// archiveFields are the only fields read from a Release file for what they
// say, each in lower case as isField takes it.
var archiveFields = []string{"origin", "label", "codename", "notautomatic", "butautomaticupgrades"}

// fileListFields are the fields of a Release file under which it lists its
// files, one a line: a checksum, a size and a path. Debian's and Ubuntu's own
// archives were read with their lists under SHA256, some under MD5Sum and
// SHA1 as well (2026-10-09).
var fileListFields = []string{"md5sum", "sha1", "sha256", "sha512"}

// readArchive reads one archive's InRelease or Release file, once: who the
// archive says it is, and which of the lists asked about it names among its
// files. asked holds what is left of each such list's name after the
// archive's own, like "main_binary-arm64_Packages", and what comes back
// holds those the file names.
//
// Who it says it is is held against the closed list for this host: a word is
// said only for an archive of the host's own distribution, for the host's own
// release. An archive that says "Ubuntu" on a Debian host is another
// archive, whatever codename it gives.
//
// The file is read to its end, because nothing fixes the order of its
// fields: the two flags stand after the others on Ubuntu's backports, read on
// 2026-10-06, and a flag that was missed would make a backport an update. A
// field is a name at the start of a line, read as aptField reads it. A line
// that starts with a blank is the line before it going on, and it is read
// only under a field that lists files. In an InRelease the fields follow the
// armour of a signed message and end where the signature starts. The
// signature is not checked: apt checked it before it kept the file, and this
// reader follows what the host's own apt accepted and nothing more. A field
// said twice says nothing, so the archive is then one of the others. apt
// takes the last of the two, measured on 2026-10-09, and this reader takes
// neither.
//
// It is read as a stream, a line at a time. The list of files is the long
// part, 255,850 bytes in all on Ubuntu 24.04, and none of it is kept: each
// of its lines is held against the few names asked about and let go.
func readArchive(path string, dist *hostdoc.Distribution, asked map[string]bool) (aptArchive, map[string]bool, error) {
	f, err := openAptRelease(path)
	if err != nil {
		return aptArchive{}, nil, err
	}
	defer f.Close()
	cr := &countingReader{r: io.LimitReader(f, int64(maxReleaseBytes)+1)}
	sc := bufio.NewScanner(cr)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
	values, said := map[string]string{}, map[string]int{}
	named := map[string]bool{}
	first, inArmour, inFileList := true, false, false
	for sc.Scan() {
		line := sc.Bytes()
		if first {
			first = false
			if string(line) == "-----BEGIN PGP SIGNED MESSAGE-----" {
				inArmour = true
				continue
			}
		}
		if inArmour {
			// The armour's own headers end at the first empty line.
			inArmour = len(line) != 0
			continue
		}
		if bytes.HasPrefix(line, []byte("-----BEGIN PGP SIGNATURE-----")) {
			break
		}
		if len(line) == 0 {
			inFileList = false
			continue
		}
		if goesOn(line) {
			if inFileList {
				if tail := listNamedBy(line, asked); tail != "" {
					named[tail] = true
				}
			}
			continue
		}
		name, value, ok := aptField(line)
		inFileList = false
		if !ok {
			continue
		}
		for _, lists := range fileListFields {
			if isField(name, lists) {
				inFileList = true
			}
		}
		for _, wanted := range archiveFields {
			if isField(name, wanted) {
				values[wanted] = string(value)
				said[wanted]++
			}
		}
	}
	if err := sc.Err(); err != nil || cr.n > maxReleaseBytes {
		return aptArchive{}, nil, errListNotUnderstood
	}
	for _, count := range said {
		if count > 1 {
			return aptArchive{}, named, nil
		}
	}
	a := aptArchive{
		notAutomatic:         aptSaysYes(values["notautomatic"]),
		butAutomaticUpgrades: aptSaysYes(values["butautomaticupgrades"]),
	}
	// A host whose os-release names no distribution or no release has no
	// archive of its own to tell from the others.
	if dist == nil || dist.VersionCodename == "" {
		return a, named, nil
	}
	codename := dist.VersionCodename
	origin, label, name := values["origin"], values["label"], values["codename"]
	switch {
	case dist.ID == "debian" && origin == "Debian" && label == "Debian" &&
		(name == codename || name == codename+"-updates"):
		a.word = "debian"
	case dist.ID == "debian" && origin == "Debian" && label == "Debian-Security" && name == codename+"-security":
		a.word = "debian-security"
	case dist.ID == "debian" && origin == "Debian Backports" && label == "Debian Backports" &&
		name == codename+"-backports" && (a.notAutomatic || a.butAutomaticUpgrades):
		// Debian's backports are Debian's own archive, and apt installs
		// nothing from them by itself, which their two flags say
		// (backports.debian.org, Instructions, read on 2026-10-27: "All
		// backports are deactivated by default"). So they carry Debian's
		// word and their flags, as Ubuntu's backports carry Ubuntu's. Only
		// with a flag: without one, a backport would read as an update.
		// The sloppy archive says another codename and stays another
		// archive.
		a.word = "debian"
	case dist.ID == "ubuntu" && origin == "Ubuntu" && label == "Ubuntu" && name == codename:
		a.word = "ubuntu"
	}
	return a, named, nil
}

// listNamedBy returns which of the lists asked about one line of a Release
// file's list of files names, or "" when it names none of them.
//
// Such a line is a checksum, a size and a path, as in
// " 0123abcd  1234 main/binary-arm64/Packages". apt keeps the list fetched
// from that path under the archive's own name with the path after it, each
// "/" written as "_". So the line names the list whose name ends that way.
// Only the plain path names a list. "Packages.xz" beside it is the same list
// as the archive sends it, and names nothing here: every archive of Debian's
// and Ubuntu's own that was read names the plain path too.
//
// A path is held to letters, digits and ". + - /". apt writes other
// characters into a file's name in another way, a "_" as "%5f" (measured on
// 2026-10-09), so a path that holds one stands for no name this reader could
// work out, and with the "_" left as it is it could stand for the name of
// another archive's list.
func listNamedBy(line []byte, asked map[string]bool) string {
	path, ok := fileLinePath(line)
	if !ok || !bytes.HasSuffix(path, []byte("Packages")) {
		return ""
	}
	for tail := range asked {
		if nameOfPath(tail, path) {
			return tail
		}
	}
	return ""
}

// fileLinePath returns the path one line of a list of files names: the last
// of its three words, after a checksum and a size.
func fileLinePath(line []byte) ([]byte, bool) {
	line = bytes.Trim(line, " \t\r")
	last := bytes.LastIndexAny(line, " \t")
	if last < 0 {
		return nil, false
	}
	path, before := line[last+1:], bytes.TrimRight(line[:last], " \t")
	gap := bytes.IndexAny(before, " \t")
	if gap <= 0 {
		return nil, false
	}
	size := bytes.TrimLeft(before[gap:], " \t")
	if len(size) == 0 {
		return nil, false
	}
	for _, c := range size {
		if c < '0' || c > '9' {
			return nil, false
		}
	}
	return path, true
}

// nameOfPath reports whether tail is what apt makes of path in a list's
// name: the same bytes, with "_" where the path has "/".
func nameOfPath(tail string, path []byte) bool {
	if len(tail) != len(path) {
		return false
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c == '/':
			c = '_'
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '+', c == '-':
		default:
			return false
		}
		if tail[i] != c {
			return false
		}
	}
	return true
}

// releaseBase returns an archive's own name in apt's folder: its Release
// file's name without the ending. "<mirror>_dists_<suite>_InRelease" gives
// "<mirror>_dists_<suite>", and every list of that archive is kept under a
// name that starts with it.
func releaseBase(name string) (string, bool) {
	if base, ok := strings.CutSuffix(name, "_InRelease"); ok {
		return base, true
	}
	return strings.CutSuffix(name, "_Release")
}

// whoseLists says of each list which archive it is one of. releases holds
// each archive's own name and its Release file's.
//
// A list is an archive's only when that archive's Release file names it
// among its files. That its name starts with the archive's is not enough:
// apt keeps the list of an archive that has no Release file of its own, and
// where such an archive stands under the folder of one that has, its list's
// name starts with the other's (measured on 2026-10-09). A list no Release
// file names has no word of any archive, so it is another archive's, as it
// is to apt, which said of such a list no origin and no label. A list two
// archives name is neither's.
//
// Each Release file is read once in a run, whatever the number of its lists,
// and one that could name no list in the folder is not read at all.
func whoseLists(dir string, lists []string, releases map[string]string, dist *hostdoc.Distribution) (map[string]aptArchive, error) {
	bases := make([]string, 0, len(releases))
	for base := range releases {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	archives, namedBy := map[string]aptArchive{}, map[string]int{}
	for _, base := range bases {
		asked := map[string]bool{}
		for _, list := range lists {
			if tail, ok := strings.CutPrefix(list, base+"_"); ok {
				asked[tail] = true
			}
		}
		if len(asked) == 0 {
			continue
		}
		archive, named, err := readArchive(filepath.Join(dir, releases[base]), dist, asked)
		if err != nil {
			return nil, err
		}
		for tail := range named {
			list := base + "_" + tail
			archives[list] = archive
			namedBy[list]++
		}
	}
	for list, count := range namedBy {
		if count > 1 {
			delete(archives, list)
		}
	}
	return archives, nil
}

// isPlainList reports whether a file in apt's folder is a list of packages
// kept as plain text.
func isPlainList(name string) bool {
	return strings.HasSuffix(name, "_Packages") && name != "_Packages"
}

// isCompressedList reports whether a file is a list apt keeps compressed.
func isCompressedList(name string) bool {
	for _, suffix := range compressedListSuffixes {
		if strings.HasSuffix(name, "_Packages"+suffix) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------ a list

// readAptList reads one list as a stream, never the whole of it, and returns
// the stanzas of the packages asked for. It stops with an error at anything
// it does not understand, because a list read wrongly is worse than a list
// not read.
//
// What it understands is a list as apt reads one: stanzas with an empty line
// between them, each line of a stanza a field (aptField) or the line before
// it going on, and a Package field in every stanza. Bytes that are not that
// are no list. apt said of such a file "Encountered a section with no
// Package: header" and could then read none of its lists (measured on
// 2026-10-09), and a reader that took it for a list with nothing in it would
// call the read complete. Where one line of a list is not understood apt
// went on in silence and knew only some of its packages. This reader stops.
func readAptList(path string, wanted map[string]bool, budget *int64) ([]listedVersion, error) {
	f, err := openAptList(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(io.LimitReader(f, int64(maxAptListBytes)+1), 256*1024)
	var found []listedVersion
	perName := map[string]int{}
	var read int64
	// The stanza being read: how many fields it has so far, its three fields
	// that are kept, and how often each was said.
	var name, version, arch string
	var fields, names, versions, archs int
	endStanza := func() error {
		defer func() { name, version, arch, fields, names, versions, archs = "", "", "", 0, 0, 0, 0 }()
		if names > 1 || (fields > 0 && names == 0) {
			return errListNotUnderstood
		}
		if names == 0 || !wanted[name] {
			return nil
		}
		if versions != 1 || archs != 1 || !hostdoc.PackageVersion(version) || !hostdoc.PackageText(arch) {
			return errListNotUnderstood
		}
		if perName[name]++; perName[name] > maxVersionsPerList {
			return errListNotUnderstood
		}
		found = append(found, listedVersion{Name: name, Version: version, Architecture: arch})
		return nil
	}
	// oneLine reads one line of a stanza, or the first piece of one that is
	// longer than the buffer.
	oneLine := func(line []byte) error {
		if len(line) == 0 {
			return endStanza()
		}
		if goesOn(line) {
			// A line can only go on from a field of the same stanza.
			if fields == 0 {
				return errListNotUnderstood
			}
			return nil
		}
		field, value, ok := aptField(line)
		if !ok {
			return errListNotUnderstood
		}
		fields++
		switch {
		case isField(field, "package"):
			name = string(value)
			names++
		case isField(field, "version"):
			version = string(value)
			versions++
		case isField(field, "architecture"):
			arch = string(value)
			archs++
		}
		return nil
	}
	for {
		line, err := r.ReadSlice('\n')
		read += int64(len(line))
		if lineErr := oneLine(bytes.TrimRight(line, "\r\n")); lineErr != nil {
			return nil, lineErr
		}
		// A line longer than the buffer comes in pieces. The pieces after
		// the first are the same line, and none of them starts a field.
		for err == bufio.ErrBufferFull {
			var more []byte
			more, err = r.ReadSlice('\n')
			read += int64(len(more))
		}
		if read > int64(maxAptListBytes) {
			return nil, errPastCap
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if *budget -= read; *budget < 0 {
		return nil, errPastCap
	}
	return found, endStanza()
}

// -------------------------------------------------------------- the offers

// collectOffers reads what the host's apt lists offer for the packages asked
// for. kept is what the last complete read left, or nil. It returns the
// offers, whether the packages were cut, the verdict for the apt_lists
// source, and what to keep for the next run.
//
// The verdict is collected only when every list in the folder was read
// whole, from the file or from what was kept of it. Anything less and there
// are no offers at all and nothing is kept.
func collectOffers(root string, dist *hostdoc.Distribution, asked []askedPackage, kept []byte) ([]hostdoc.PackageOffers, bool, hostdoc.Section, []byte) {
	if len(asked) == 0 {
		// Nothing to ask about, so nothing is read: the lists are a
		// hundred megabytes and the answer would be empty.
		return nil, false, hostdoc.Section{Status: hostdoc.StatusNotCollected}, nil
	}
	cut := len(asked) > hostdoc.MaxOfferPackages
	if cut {
		asked = asked[:hostdoc.MaxOfferPackages]
	}
	dir := filepath.Join(root, aptListsDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false, fileVerdict(err), nil
	}
	var lists []string
	// Each archive's own name in the folder, and its Release file's.
	releases := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case isCompressedList(name):
			return nil, false, fileVerdict(errListNotUnderstood), nil
		case isPlainList(name):
			if !entry.Type().IsRegular() {
				return nil, false, fileVerdict(errListNotUnderstood), nil
			}
			lists = append(lists, name)
		default:
			base, isRelease := releaseBase(name)
			if !isRelease || !entry.Type().IsRegular() {
				continue
			}
			// InRelease is taken before Release, as apt does.
			if _, has := releases[base]; !has || strings.HasSuffix(name, "_InRelease") {
				releases[base] = name
			}
		}
	}
	archives, err := whoseLists(dir, lists, releases, dist)
	if err != nil {
		return nil, false, fileVerdict(err), nil
	}

	wanted := map[string]bool{}
	names := make([]string, 0, len(asked))
	for _, a := range asked {
		wanted[a.name] = true
		names = append(names, a.name)
	}
	before := map[string]keptList{}
	if k := understoodKept(kept); k != nil && k.covers(asked) {
		for _, l := range k.Lists {
			before[l.Name] = l
		}
	}

	keep := keptLists{KeptVersion: keptVersion, Asked: names, Lists: []keptList{}}
	budget := int64(maxAptListsTotalBytes)
	for _, name := range lists {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, false, fileVerdict(err), nil
		}
		now := keptList{Name: name, Size: info.Size(), MtimeNs: info.ModTime().UnixNano(), Found: []listedVersion{}}
		if was, ok := before[name]; ok && was.Size == now.Size && was.MtimeNs == now.MtimeNs {
			for _, v := range was.Found {
				if wanted[v.Name] {
					now.Found = append(now.Found, v)
				}
			}
			keep.Lists = append(keep.Lists, now)
			continue
		}
		found, err := readAptList(path, wanted, &budget)
		if err != nil {
			return nil, false, fileVerdict(err), nil
		}
		// A list apt replaced while it was read is not the list that was
		// read. The next run reads it again.
		after, err := os.Lstat(path)
		if err != nil || after.Size() != now.Size || after.ModTime().UnixNano() != now.MtimeNs {
			return nil, false, fileVerdict(errListNotUnderstood), nil
		}
		now.Found = append(now.Found, found...)
		keep.Lists = append(keep.Lists, now)
	}

	offers := make([]hostdoc.PackageOffers, 0, len(asked))
	for _, a := range asked {
		offers = append(offers, offersOf(a, keep.Lists, archives))
	}
	keepBytes, err := json.Marshal(keep)
	if err != nil {
		keepBytes = nil
	}
	return offers, cut, hostdoc.Section{Status: hostdoc.StatusCollected}, keepBytes
}

// offersOf builds one package's entry from every list's stanzas for it.
func offersOf(a askedPackage, lists []keptList, archives map[string]aptArchive) hostdoc.PackageOffers {
	out := hostdoc.PackageOffers{Name: a.name}
	seen := map[hostdoc.Offer]bool{}
	for _, l := range lists {
		archive := archives[l.Name]
		for _, v := range l.Found {
			// A stanza for another architecture is not this package's
			// update. One for "all" is every architecture's.
			if v.Name != a.name || !(a.archs[v.Architecture] || v.Architecture == "all" || a.archs["all"]) {
				continue
			}
			if archive.word == "" {
				out.OtherOffers = true
				if a.versions[v.Version] {
					out.OtherOffersInstalled = true
				}
				continue
			}
			offer := hostdoc.Offer{Version: v.Version, Archive: archive.word,
				NotAutomatic: archive.notAutomatic, ButAutomaticUpgrades: archive.butAutomaticUpgrades}
			if !seen[offer] {
				seen[offer] = true
				out.Offered = append(out.Offered, offer)
			}
		}
	}
	sort.Slice(out.Offered, func(i, j int) bool { return hostdoc.OfferBefore(out.Offered[i], out.Offered[j]) })
	if len(out.Offered) > hostdoc.MaxOffersPerPackage {
		out.Offered = out.Offered[:hostdoc.MaxOffersPerPackage]
		out.OfferedCut = true
	}
	return out
}
