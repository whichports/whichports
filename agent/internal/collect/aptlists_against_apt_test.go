package collect

// The apt lists reader, held against apt itself.
//
// aptlists_test.go holds the reader to fixtures in the one spelling every
// archive read so far uses. The tests here hold it to what apt does with the
// same files in other spellings and other layouts, because the reader's
// answer is only worth what the host's own apt would say of the same folder.
//
// Where the facts come from. Measured on 2026-10-09 with the apt of a Debian
// 12 install in a container, apt 2.6.1, with no network: one archive made on
// the machine for each case, set up with "trusted=yes", then `apt-get update`
// and what `apt-cache policy` said. No real archive was seen to write any of
// these spellings. What was measured is that apt reads each of them, so a
// reader that passed over them would say less than the host's own apt
// believes while its report still read collected.
//
// How an archive names its lists was read the same day on the lists that
// apt fetched from Debian 12's and Ubuntu 24.04's own archives: every list
// kept was named in its archive's InRelease by its plain path, like
// "main/binary-arm64/Packages", under SHA256, and on some under MD5Sum and
// SHA1 as well.
//
// The fixtures are built by each test, like the ones beside them.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// countReleaseReads counts how many Release files a run opens.
func countReleaseReads(t *testing.T) *int {
	t.Helper()
	n := 0
	real := openAptRelease
	openAptRelease = func(path string) (*os.File, error) {
		n++
		return real(path)
	}
	t.Cleanup(func() { openAptRelease = real })
	return &n
}

// flagOffers is what a Debian 12 host's lists offer for OpenSSH from one
// archive that says it is Debian's own and adds the given lines.
func flagOffers(t *testing.T, lines ...string) []hostdoc.Offer {
	t.Helper()
	tr := sshHost(t)
	fields := append(append([]string{}, debianMain...), lines...)
	tr.archive("deb.debian.org_debian_dists_bookworm", fields, offered("openssh-server", "1:9.9p1-1", "arm64"))
	sec := tr.collect("ssh.service")
	if got := listsVerdict(sec); got != hostdoc.StatusCollected {
		t.Fatalf("apt_lists reads %q, want collected", got)
	}
	return offersFor(t, sec, "openssh-server").Offered
}

// ------------------------------------------------ an archive's two flags

// apt reads an archive's two flags in more spellings than one. Each line
// below got the weight 1 from apt, where an archive with no flag got 500:
// the value as yes, true, on, enable or with in lower case, with a capital
// and in upper case, as 1 or 01, the field's name in lower or upper case, and
// the colon followed by nothing, by two spaces or by a tab, and a space after
// the value. A reader that knows only "NotAutomatic: yes" calls each of them
// an archive with no flag, and a missed flag makes a backport an update.
func TestAFlagIsReadInEverySpellingAptReads(t *testing.T) {
	for _, spelling := range []string{
		"NotAutomatic: yes", "NotAutomatic: Yes", "NotAutomatic: YES",
		"NotAutomatic: true", "NotAutomatic: True", "NotAutomatic: TRUE",
		"NotAutomatic: on", "NotAutomatic: On", "NotAutomatic: ON",
		"NotAutomatic: enable", "NotAutomatic: Enable", "NotAutomatic: ENABLE",
		"NotAutomatic: with", "NotAutomatic: With", "NotAutomatic: WITH",
		"NotAutomatic: 1", "NotAutomatic: 01",
		"notautomatic: yes", "NOTAUTOMATIC: yes",
		"NotAutomatic:yes", "NotAutomatic:  yes", "NotAutomatic: yes ", "NotAutomatic:\tyes",
	} {
		t.Run(spelling, func(t *testing.T) {
			offers := flagOffers(t, spelling)
			if len(offers) != 1 || offers[0].Archive != "debian" || !offers[0].NotAutomatic || offers[0].ButAutomaticUpgrades {
				t.Errorf("apt holds this archive back, and the report says %+v", offers)
			}
		})
	}
	// The second flag, in the one other spelling measured: apt gave the
	// archive the weight 100, which it gives only when both flags are read.
	t.Run("ButAutomaticUpgrades: Yes", func(t *testing.T) {
		offers := flagOffers(t, "NotAutomatic: yes", "ButAutomaticUpgrades: Yes")
		if len(offers) != 1 || !offers[0].NotAutomatic || !offers[0].ButAutomaticUpgrades {
			t.Errorf("apt reads both flags of this archive, and the report says %+v", offers)
		}
	})
}

// And what apt took as no flag is no flag. Each line below left the archive
// at the weight 500. Of the last five apt said "Unknown flag value" and went
// on as if the field were not there. The reader says what apt believes, so
// it does the same: the archive is still the distribution's own, with no
// flag.
func TestAFlagAptReadsAsNoIsNoFlag(t *testing.T) {
	for _, spelling := range []string{
		"NotAutomatic: no", "NotAutomatic: No", "NotAutomatic: NO",
		"NotAutomatic: false", "NotAutomatic: False", "NotAutomatic: off",
		"NotAutomatic: disable", "NotAutomatic: without", "NotAutomatic: 0",
		"NotAutomatic: ", "NotAutomatic:",
		"NotAutomatic: 2", "NotAutomatic: -1", "NotAutomatic: y", "NotAutomatic: maybe", "NotAutomatic: yes please",
	} {
		t.Run(spelling, func(t *testing.T) {
			offers := flagOffers(t, spelling)
			if len(offers) != 1 || offers[0].Archive != "debian" || offers[0].NotAutomatic {
				t.Errorf("apt gives this archive the weight of one with no flag, and the report says %+v", offers)
			}
		})
	}
}

// What an archive says of itself is read in the spellings apt reads too. apt
// said "o=Debian" of an archive that wrote its origin in each of these ways.
// The value itself is held as it was: "debian" in lower case is not Debian,
// which TestAnArchiveThatDoesNotFitTheClosedListIsAnother holds.
func TestAnArchivesOwnWordsAreReadInEverySpellingAptReads(t *testing.T) {
	for _, origin := range []string{
		"origin: Debian", "ORIGIN: Debian", "Origin:Debian", "Origin:  Debian", "Origin:\tDebian", "Origin: Debian ",
	} {
		t.Run(origin, func(t *testing.T) {
			tr := sshHost(t)
			tr.archive("deb.debian.org_debian_dists_bookworm", []string{origin, "label: Debian", "CODENAME:bookworm"},
				offered("openssh-server", "1:9.2p1-2", "arm64"))
			o := offersFor(t, tr.collect("ssh.service"), "openssh-server")
			if got, want := said(o), "debian 1:9.2p1-2"; got != want || o.OtherOffers {
				t.Errorf("offered %q and other %v, want %q: apt reads this archive as Debian's", got, o.OtherOffers, want)
			}
		})
	}
	// A field said twice says nothing, in whatever case each is written. Of
	// these two apt took the last, and said "o=Debian". This reader takes
	// neither, and the archive is one of the others.
	t.Run("an origin said twice in two cases", func(t *testing.T) {
		tr := sshHost(t)
		tr.archive("deb.debian.org_debian_dists_bookworm", []string{"Origin: Acme Corp", "origin: Debian", "Label: Debian", "Codename: bookworm"},
			offered("openssh-server", "1:9.2p1-2", "arm64"))
		o := offersFor(t, tr.collect("ssh.service"), "openssh-server")
		if len(o.Offered) != 0 || !o.OtherOffers {
			t.Errorf("an archive that says its origin twice was read as %+v", o)
		}
	})
}

// ------------------------------------------------ a list's stanzas

// apt reads a stanza whose field names are in another case, one whose colon
// is followed by nothing, by two spaces or by a tab, and one whose values
// have a space, a tab or a carriage return after them. Each of the eight was
// a package apt-cache policy knew, with its version.
//
// Here the stanza stands in an archive that is not the distribution's and
// offers the very version that is installed. Passed over, the report would
// say no other archive offers the package, which is how a build that did not
// come from the distribution is taken for one that did.
func TestAStanzaAptReadsIsNotPassedOver(t *testing.T) {
	// The three fields as they are written, and what ends each line.
	spellings := map[string][4]string{
		"names in lower case":      {"package: ", "version: ", "architecture: ", "\n"},
		"names in upper case":      {"PACKAGE: ", "VERSION: ", "ARCHITECTURE: ", "\n"},
		"nothing after the colon":  {"Package:", "Version:", "Architecture:", "\n"},
		"two spaces after it":      {"Package:  ", "Version:  ", "Architecture:  ", "\n"},
		"a tab after the colon":    {"Package:\t", "Version:\t", "Architecture:\t", "\n"},
		"a space after the value":  {"Package: ", "Version: ", "Architecture: ", " \n"},
		"a tab after the value":    {"Package: ", "Version: ", "Architecture: ", "\t\n"},
		"a return after the value": {"Package: ", "Version: ", "Architecture: ", "\r\n"},
	}
	for name, as := range spellings {
		t.Run(name, func(t *testing.T) {
			tr := sshHost(t)
			debianLists(tr)
			tr.archive("apt.acme-internal.example_debian_dists_bookworm", acme,
				as[0]+"openssh-server"+as[3]+as[1]+"1:9.0p1-1"+as[3]+as[2]+"arm64"+as[3]+"Description: a package\n")
			sec := tr.collect("ssh.service")
			if got := listsVerdict(sec); got != hostdoc.StatusCollected {
				t.Fatalf("apt_lists reads %q, want collected: apt reads this list", got)
			}
			if o := offersFor(t, sec, "openssh-server"); !o.OtherOffers || !o.OtherOffersInstalled {
				t.Errorf("another archive offers the installed version in a stanza apt reads, and the report says %+v", o)
			}
		})
	}
}

// Bytes that are no list, under a list's name. apt kept such a file from an
// archive with no Release file and then could parse none of its lists:
// "Encountered a section with no Package: header". A reader that read the
// file to its end, found no stanza in it and took it for a list that offers
// nothing would call the read complete.
//
// It takes a list damaged after apt checked it against its archive's Release
// file, so it is the least likely of the cases here.
func TestBytesThatAreNoListAreNotReadAsAnEmptyList(t *testing.T) {
	// The same bytes every run, from a counter, and none of them a field.
	junk := make([]byte, 4096)
	x := uint32(1)
	for i := range junk {
		x = x*1103515245 + 12345
		junk[i] = byte(x >> 16)
	}
	tr := sshHost(t)
	debianLists(tr)
	// The one list of an archive of its own, which its Release file names.
	tr.archive("apt.acme-internal.example_debian_dists_bookworm", acme, string(junk))
	sec := tr.collect("ssh.service")
	if got := listsVerdict(sec); got != hostdoc.StatusReadError {
		t.Errorf("apt_lists reads %q with a list that holds no stanza and no line of a list, want read_error", got)
	}
	if len(sec.Offers) != 0 {
		t.Errorf("offers beside a list that was not understood: %+v", sec.Offers)
	}
}

// A list is stanzas of fields. One line that is neither a field, nor the
// line before it going on, nor empty, and the file is not a list this reader
// understands. The second case is the one apt names in its own words.
//
// apt itself is not so strict, and not to its credit: of a list with a line
// that has no colon after a stanza, it knew that stanza's package and not the
// next one's, and said nothing. This reader does not read a list by halves.
func TestALineThatIsNoLineOfAListStopsTheRead(t *testing.T) {
	good := offered("openssh-server", "1:9.2p1-2", "arm64")
	cases := map[string]string{
		"a line with no colon":             good + "this line is no field\n",
		"a stanza with no Package":         "Version: 5.9-4\nArchitecture: arm64\n\n" + good,
		"a line that goes on from nothing": " goes on\n" + good,
		"the same after an empty line":     good + "\n goes on\n",
		"a blank in a field's name":        "Package: zsh\nVer sion: 5.9-4\nArchitecture: arm64\n\n" + good,
		"a line that starts with a colon":  good + ": no name\n",
		"a byte that is no text in a name": "Pack\x00age: zsh\n\n" + good,
	}
	for name, list := range cases {
		t.Run(name, func(t *testing.T) {
			tr := sshHost(t)
			tr.archive("deb.debian.org_debian_dists_bookworm", debianMain, list)
			sec := tr.collect("ssh.service")
			if got := listsVerdict(sec); got != hostdoc.StatusReadError {
				t.Errorf("apt_lists reads %q, want read_error", got)
			}
			if len(sec.Offers) != 0 {
				t.Errorf("offers from a list that was not understood: %+v", sec.Offers)
			}
		})
	}
}

// Empty lines are only what stands between stanzas: one at the start of a
// list, several between two stanzas and several at its end change nothing,
// and neither does a list that ends without a line's end.
func TestEmptyLinesBetweenStanzasAreOnlyThat(t *testing.T) {
	tr := sshHost(t)
	tr.archive("deb.debian.org_debian_dists_bookworm", debianMain,
		"\n\n"+offered("zsh", "5.9-4", "arm64")+"\n\n\n"+offered("openssh-server", "1:9.2p1-2", "arm64")+"\n\n")
	tr.archive("deb.debian.org_debian_dists_bookworm-updates", debianUpdates,
		"Package: openssh-server\r\nVersion: 1:9.2p1-3\r\nArchitecture: arm64")
	if got, want := said(offersFor(t, tr.collect("ssh.service"), "openssh-server")), "debian 1:9.2p1-2, debian 1:9.2p1-3"; got != want {
		t.Errorf("offered %q, want %q", got, want)
	}
}

// ------------------------------------------------ whose list it is

// A list is an archive's only when that archive's Release file names it.
// apt keeps the list of an archive that has no Release file of its own, and
// when that archive stands under the folder of one that has, its list's name
// starts with the other's. Measured: apt kept
// "<mirror>_dists_bookworm_acme_main_binary-arm64_Packages" beside
// "<mirror>_dists_bookworm_Release", each a plain file, and said of the first
// "release c=main,b=arm64", no origin and no label, and of the second
// "release o=Debian" and "l=Debian".
//
// A reader that went by the start of the name would give the first list the
// second's word, and its versions would leave the host as the
// distribution's own.
func TestAListAnArchivesReleaseFileDoesNotNameIsNotThatArchives(t *testing.T) {
	tr := sshHost(t)
	// inRelease names one list, main/binary-arm64/Packages.
	tr.archive("mirror.example_debian_dists_bookworm", debianMain, offered("openssh-server", "1:9.2p1-2", "arm64"))
	tr.file(listsDir+"mirror.example_debian_dists_bookworm_acme_main_binary-arm64_Packages",
		offered("openssh-server", "1:9.9p9-1+acme7", "arm64"))
	sec := tr.collect("ssh.service")
	if sent := string(mustMarshal(t, sec)); strings.Contains(sent, "9.9p9") {
		t.Errorf("a version from a list no Release file names left the host:\n%s", sent)
	}
	if got := listsVerdict(sec); got != hostdoc.StatusCollected {
		t.Fatalf("apt_lists reads %q, want collected", got)
	}
	o := offersFor(t, sec, "openssh-server")
	if got, want := said(o), "debian 1:9.2p1-2"; got != want || !o.OtherOffers || o.OtherOffersInstalled {
		t.Errorf("offered %q, other %v, installed %v, want %q and another archive that offers another version",
			got, o.OtherOffers, o.OtherOffersInstalled, want)
	}
}

// A list with no Release file in the folder at all has no word of any
// archive. It is another archive's, as it is to apt, and it is read like
// any other: the two facts, and none of its versions.
func TestAListNoReleaseFileNamesIsAnotherArchives(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	tr.file(listsDir+"mirror.example_local_._Packages",
		offered("openssh-server", "1:9.0p1-1", "arm64")+"\n"+offered("openssh-server", "1:9.9p9-1+acme7", "arm64"))
	sec := tr.collect("ssh.service")
	if got := listsVerdict(sec); got != hostdoc.StatusCollected {
		t.Fatalf("apt_lists reads %q, want collected", got)
	}
	o := offersFor(t, sec, "openssh-server")
	if got, want := said(o), "debian 1:9.2p1-2, debian-security 1:9.2p1-2+deb12u10"; got != want {
		t.Errorf("offered %q, want only the distribution's own %q", got, want)
	}
	if !o.OtherOffers || !o.OtherOffersInstalled {
		t.Errorf("a list of no archive offers the installed version, and the entry says %+v", o)
	}
	if sent := string(mustMarshal(t, sec)); strings.Contains(sent, "9.9p9") || strings.Contains(sent, "mirror.example") {
		t.Errorf("something of a list no Release file names left the host:\n%s", sent)
	}
}

// Two archives whose Release files both name one list: an archive at
// "dists/bookworm" with a component "updates/main", and one at
// "dists/bookworm/updates" with a component "main", come to the same name in
// apt's folder. Nothing here says which of them the list came from, so it is
// neither's, whatever the two say of themselves.
func TestAListTwoArchivesNameIsNeithers(t *testing.T) {
	tr := sshHost(t)
	tr.file(listsDir+"mirror.example_debian_dists_bookworm_Release",
		strings.Join(debianMain, "\n")+"\nSHA256:\n 00 1 updates/main/binary-arm64/Packages\n")
	tr.file(listsDir+"mirror.example_debian_dists_bookworm_updates_Release",
		strings.Join(debianMain, "\n")+"\nSHA256:\n 00 1 main/binary-arm64/Packages\n")
	tr.file(listsDir+"mirror.example_debian_dists_bookworm_updates_main_binary-arm64_Packages",
		offered("openssh-server", "1:9.2p1-2", "arm64"))
	sec := tr.collect("ssh.service")
	if got := listsVerdict(sec); got != hostdoc.StatusCollected {
		t.Fatalf("apt_lists reads %q, want collected", got)
	}
	if o := offersFor(t, sec, "openssh-server"); len(o.Offered) != 0 || !o.OtherOffers {
		t.Errorf("a list two archives name was read as %+v", o)
	}
}

// What names a list is its plain path, on a line of three words, a checksum,
// a size and the path, under one of the fields that list an archive's files.
// The archive here says it is Debian's own in every case, so a list it names
// is said as debian and a list it does not name is another archive's.
func TestOnlyThePlainPathUnderAListOfFilesNamesAList(t *testing.T) {
	const plain = "main_binary-arm64_Packages"
	cases := map[string]struct {
		files string
		list  string
		named bool
	}{
		"under SHA256":                 {"SHA256:\n 00 1 main/binary-arm64/Packages\n", plain, true},
		"under MD5Sum":                 {"MD5Sum:\n 00 1 main/binary-arm64/Packages\n", plain, true},
		"under SHA1 and SHA512":        {"SHA1:\n 00 1 main/binary-all/Packages\nSHA512:\n 00 1 main/binary-arm64/Packages\n", plain, true},
		"the field in another case":    {"sha256:\n 00 1 main/binary-arm64/Packages\n", plain, true},
		"many blanks between words":    {"SHA256:\n 00       1234567 main/binary-arm64/Packages\n", plain, true},
		"tabs between the words":       {"SHA256:\n\t00\t1\tmain/binary-arm64/Packages\n", plain, true},
		"after other files":            {"SHA256:\n 00 1 main/binary-arm64/Packages.xz\n 00 1 main/binary-arm64/Packages\n", plain, true},
		"a component in two parts":     {"SHA256:\n 00 1 updates/main/binary-arm64/Packages\n", "updates_main_binary-arm64_Packages", true},
		"a list that is the whole":     {"SHA256:\n 00 1 Packages\n", "Packages", true},
		"only the compressed list":     {"SHA256:\n 00 1 main/binary-arm64/Packages.xz\n 00 1 main/binary-arm64/Packages.gz\n", plain, false},
		"another architecture's":       {"SHA256:\n 00 1 main/binary-amd64/Packages\n", plain, false},
		"another component's":          {"SHA256:\n 00 1 contrib/binary-arm64/Packages\n", plain, false},
		"no list of files at all":      {"", plain, false},
		"under a field of another":     {"Description: a list\n 00 1 main/binary-arm64/Packages\n", plain, false},
		"after an empty line":          {"SHA256:\n\n 00 1 main/binary-arm64/Packages\n", plain, false},
		"a line of four words":         {"SHA256:\n 00 1 main/binary-arm64/Packages more\n", plain, false},
		"a line of two words":          {"SHA256:\n 1 main/binary-arm64/Packages\n", plain, false},
		"a size that is no number":     {"SHA256:\n 00 big main/binary-arm64/Packages\n", plain, false},
		"a path with an underscore":    {"SHA256:\n 00 1 acme_main/binary-arm64/Packages\n", "acme_main_binary-arm64_Packages", false},
		"a path that only starts so":   {"SHA256:\n 00 1 main/binary-arm64/Packages/more\n", plain, false},
		"a path that only ends so":     {"SHA256:\n 00 1 more/main/binary-arm64/Packages\n", plain, false},
		"a path written with the name": {"SHA256:\n 00 1 main_binary-arm64_Packages\n", plain, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tr := sshHost(t)
			base := "mirror.example_debian_dists_bookworm"
			tr.file(listsDir+base+"_Release", strings.Join(debianMain, "\n")+"\n"+c.files)
			tr.file(listsDir+base+"_"+c.list, offered("openssh-server", "1:9.2p1-2", "arm64"))
			sec := tr.collect("ssh.service")
			if got := listsVerdict(sec); got != hostdoc.StatusCollected {
				t.Fatalf("apt_lists reads %q, want collected", got)
			}
			o := offersFor(t, sec, "openssh-server")
			if c.named && (said(o) != "debian 1:9.2p1-2" || o.OtherOffers) {
				t.Errorf("the archive names its list, and the entry says %+v", o)
			}
			if !c.named && (len(o.Offered) != 0 || !o.OtherOffers) {
				t.Errorf("the archive does not name this list, and the entry says %+v", o)
			}
		})
	}
}

// An archive's Release file is read once in a run, however many lists the
// archive has, and one whose archive has no list in the folder is not read
// at all. What was kept of the lists spares none of it: who an archive says
// it is is asked again at every run.
func TestAnArchivesReleaseFileIsReadOnceARun(t *testing.T) {
	tr := sshHost(t)
	base := "deb.debian.org_debian_dists_bookworm"
	files := "SHA256:\n"
	for _, component := range []string{"main", "contrib", "non-free"} {
		files += " 00 1 " + component + "/binary-arm64/Packages\n"
		tr.file(listsDir+base+"_"+component+"_binary-arm64_Packages", offered("openssh-server", "1:9.2p1-2+"+component, "arm64"))
	}
	tr.file(listsDir+base+"_Release", strings.Join(debianMain, "\n")+"\n"+files)
	tr.file(listsDir+"deb.debian.org_debian_dists_bookworm-updates_InRelease", inRelease(debianUpdates))

	releases := countReleaseReads(t)
	sec, kept, lists := keeping(t, tr, nil, "ssh.service")
	want := "debian 1:9.2p1-2+contrib, debian 1:9.2p1-2+main, debian 1:9.2p1-2+non-free"
	if got := said(offersFor(t, sec, "openssh-server")); got != want {
		t.Fatalf("offered %q, want %q", got, want)
	}
	if lists != 3 || *releases != 1 {
		t.Errorf("the first run opened %d lists and %d Release files, want 3 and 1", lists, *releases)
	}
	*releases = 0
	sec, _, lists = keeping(t, tr, kept, "ssh.service")
	if got := said(offersFor(t, sec, "openssh-server")); got != want {
		t.Errorf("the second run offered %q, want %q", got, want)
	}
	if lists != 0 || *releases != 1 {
		t.Errorf("the second run opened %d lists and %d Release files, want 0 and 1", lists, *releases)
	}
}

// ------------------------------------- what is asked of every such reader
//
// Each of these is asked of a reader of files on somebody else's server.

// collectWithin runs the collector and fails the test if it is not back in
// ten seconds. A pipe nobody writes to never answers an open, so a reader
// that opens one fails its test and does not hold the whole suite.
func collectWithin(t *testing.T, tr *pkgTree) *hostdoc.PackagesSection {
	t.Helper()
	done := make(chan *hostdoc.PackagesSection, 1)
	go func() { done <- CollectPackages(tr.root, []string{"ssh.service"}) }()
	select {
	case sec := <-done:
		return sec
	case <-time.After(10 * time.Second):
		t.Fatal("the reader did not come back: it waits on something that is no plain file")
		return nil
	}
}

func pipeAt(tr *pkgTree, rel string) {
	tr.t.Helper()
	tr.remove(rel)
	if err := syscall.Mkfifo(filepath.Join(tr.root, rel), 0o644); err != nil {
		tr.t.Fatal(err)
	}
}

// A list that is not a plain file is never opened: a link is not followed
// out of the folder, and a pipe is not waited on.
//
// The first case is not made up. For an archive set up with a "file:"
// address apt itself keeps each list as a link to the file in that archive's
// folder, measured on the same day. Such a host reads read_error and has no
// offers, which is less than could be read and nothing that is wrong.
func TestAListThatIsNoPlainFileIsNeverOpened(t *testing.T) {
	list := listsDir + "deb.debian.org_debian_dists_bookworm_main_binary-arm64_Packages"
	cases := map[string]func(tr *pkgTree){
		"a list that is a link out of the folder": func(tr *pkgTree) {
			tr.file("srv/archive/Packages", offered("openssh-server", "1:9.9p9-1+acme7", "arm64"))
			tr.remove(list)
			tr.link(list, filepath.Join(tr.root, "srv/archive/Packages"))
		},
		"a list that is a link to the file beside it": func(tr *pkgTree) {
			tr.file(listsDir+"elsewhere", offered("openssh-server", "1:9.9p9-1+acme7", "arm64"))
			tr.remove(list)
			tr.link(list, "elsewhere")
		},
		"a list that is a pipe": func(tr *pkgTree) { pipeAt(tr, list) },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			tr := sshHost(t)
			tr.archive("deb.debian.org_debian_dists_bookworm", debianMain, offered("openssh-server", "1:9.2p1-2", "arm64"))
			breakIt(tr)
			opened := countListReads(t)
			sec := collectWithin(t, tr)
			sent := string(mustMarshal(t, sec))
			if got := listsVerdict(sec); got != hostdoc.StatusReadError {
				t.Errorf("apt_lists reads %q, want read_error", got)
			}
			if len(sec.Offers) != 0 || strings.Contains(sent, "9.9p9") {
				t.Errorf("offers from a folder with a list in it that is no plain file:\n%s", sent)
			}
			if *opened != 0 {
				t.Errorf("%d lists opened, want none", *opened)
			}
		})
	}
}

// An archive's Release file that is not a plain file is not read either. It
// is as if the archive had none: its list has no word of any archive and is
// another archive's. What the link points at says "Debian", and is not
// believed.
func TestAReleaseFileThatIsNoPlainFileIsNotRead(t *testing.T) {
	release := listsDir + "deb.debian.org_debian_dists_bookworm_InRelease"
	cases := map[string]func(tr *pkgTree){
		"a Release file that is a link": func(tr *pkgTree) {
			tr.file("srv/archive/InRelease", inRelease(debianMain))
			tr.remove(release)
			tr.link(release, filepath.Join(tr.root, "srv/archive/InRelease"))
		},
		"a Release file that is a pipe": func(tr *pkgTree) { pipeAt(tr, release) },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			tr := sshHost(t)
			tr.archive("deb.debian.org_debian_dists_bookworm", debianMain, offered("openssh-server", "1:9.2p1-2", "arm64"))
			breakIt(tr)
			opened := countReleaseReads(t)
			sec := collectWithin(t, tr)
			mustMarshal(t, sec)
			if got := listsVerdict(sec); got != hostdoc.StatusCollected {
				t.Fatalf("apt_lists reads %q, want collected", got)
			}
			if o := offersFor(t, sec, "openssh-server"); len(o.Offered) != 0 || !o.OtherOffers {
				t.Errorf("a list whose archive's Release file is no plain file was read as %+v", o)
			}
			if *opened != 0 {
				t.Errorf("%d Release files opened, want none", *opened)
			}
		})
	}
}

// memoryAskedFor runs the collector once and returns the section with how
// many bytes of memory the run asked for in all, from its first to its last.
func memoryAskedFor(tr *pkgTree) (*hostdoc.PackagesSection, uint64) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	sec := CollectPackages(tr.root, []string{"ssh.service"})
	runtime.ReadMemStats(&after)
	return sec, after.TotalAlloc - before.TotalAlloc
}

// A list is read as a stream. One line of 32 MiB, in a list of that size and
// a little more, costs the run less than 4 MiB of memory asked for in all,
// from the first byte to the last. The stanza before the long line and the
// one after it are both read.
func TestAListWithALineOfManyMegabytesIsNeverHeldWhole(t *testing.T) {
	tr := sshHost(t)
	const long = 32 << 20
	list := tr.archive("deb.debian.org_debian_dists_bookworm", debianMain, "Package: zsh\nVersion: 5.9-4\nArchitecture: arm64\n")
	f, err := os.OpenFile(filepath.Join(tr.root, list), os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Written in pieces, so the test does not hold the list whole either.
	piece := strings.Repeat("x", 1<<20)
	write := func(s string) {
		if _, err := f.WriteString(s); err != nil {
			t.Fatal(err)
		}
	}
	write("Package: openssh-server\nVersion: 1:9.2p1-2\nArchitecture: arm64\nDescription: ")
	for i := 0; i < long>>20; i++ {
		write(piece)
	}
	write("\n\nPackage: openssh-server\nVersion: 1:9.2p1-3\nArchitecture: arm64\n")
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	sec, asked := memoryAskedFor(tr)
	if got, want := said(offersFor(t, sec, "openssh-server")), "debian 1:9.2p1-2, debian 1:9.2p1-3"; got != want {
		t.Fatalf("offered %q, want %q", got, want)
	}
	t.Logf("a list of %d bytes read with %d bytes of memory asked for in all", long, asked)
	if asked > 4<<20 {
		t.Errorf("the run asked for %d bytes of memory to read a list of %d: it holds more than a line's piece at a time", asked, long)
	}
}

// An archive's Release file is read as a stream too. Its list of files is
// the long part, and it is held against the few lists asked about a line at
// a time and never kept. A Release file of more than 8 MiB, nearly all of it
// lines that name other files, costs the run less than 2 MiB of memory asked
// for in all, and the one line that names the list, the last of them, is
// found.
func TestAReleaseFilesListOfFilesIsNeverHeldWhole(t *testing.T) {
	tr := sshHost(t)
	tr.archive("deb.debian.org_debian_dists_bookworm", debianMain, offered("openssh-server", "1:9.2p1-2", "arm64"))
	release := filepath.Join(tr.root, listsDir+"deb.debian.org_debian_dists_bookworm_InRelease")
	f, err := os.OpenFile(release, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	other := " 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 12345678 main/source/Sources.xz\n"
	piece := strings.Repeat(other, (1<<20)/len(other))
	size := 0
	write := func(s string) {
		n, err := f.WriteString(s)
		if err != nil {
			t.Fatal(err)
		}
		size += n
	}
	write(strings.Join(debianMain, "\n") + "\nSHA256:\n")
	for size < 8<<20 {
		write(piece)
	}
	write(" 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 12345678 main/binary-arm64/Packages\n")
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	sec, asked := memoryAskedFor(tr)
	if got, want := said(offersFor(t, sec, "openssh-server")), "debian 1:9.2p1-2"; got != want {
		t.Fatalf("offered %q, want %q", got, want)
	}
	t.Logf("a Release file of %d bytes read with %d bytes of memory asked for in all", size, asked)
	if asked > 2<<20 {
		t.Errorf("the run asked for %d bytes of memory to read a Release file of %d: it keeps its list of files", asked, size)
	}
}
