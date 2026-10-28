package collect

// The apt lists reader's review.
//
// Where the fixtures come from. Every folder here is built by the test itself
// and none is a copy of an archive's file. Their shape follows what was read
// on 2026-10-06 on six installs of Debian 12 and Ubuntu 24.04, and on
// 2026-10-07 on a server running Ubuntu 26.04 (docs/RECORD.md 4.418 and
// 4.430):
//
//	a list     <mirror>_dists_<suite>_<component>_binary-<arch>_Packages,
//	           plain text, one stanza a package, a blank line between
//	its word   <mirror>_dists_<suite>_InRelease, a signed message whose
//	           fields stand before the list of files
//
// and what each archive says of itself there: Debian "Origin: Debian",
// "Label: Debian", "Codename: bookworm". Its security archive the label
// "Debian-Security" and the codename "bookworm-security". Ubuntu's three,
// and its backports, "Origin: Ubuntu", "Label: Ubuntu", "Codename: noble",
// the backports with "NotAutomatic: yes" and "ButAutomaticUpgrades: yes".
//
// The host is the OpenSSH one of packages_test.go: Debian 12, openssh-server
// 1:9.0p1-1 for arm64 behind ssh.service. The versions are made up.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

const listsDir = "var/lib/apt/lists/"

var (
	debianMain     = []string{"Origin: Debian", "Label: Debian", "Suite: oldstable", "Version: 12.13", "Codename: bookworm"}
	debianUpdates  = []string{"Origin: Debian", "Label: Debian", "Suite: oldstable-updates", "Codename: bookworm-updates"}
	debianSecurity = []string{"Origin: Debian", "Label: Debian-Security", "Suite: oldstable-security", "Codename: bookworm-security"}
	debianBackport = []string{"Origin: Debian Backports", "Label: Debian Backports", "Suite: oldstable-backports",
		"Codename: bookworm-backports", "NotAutomatic: yes", "ButAutomaticUpgrades: yes"}
	acme = []string{"Origin: Acme Corp", "Label: Acme internal builds", "Suite: stable", "Codename: bookworm"}
)

// inRelease is an archive's InRelease as apt keeps it: the armour of a signed
// message, the fields, the list of files, and a signature.
func inRelease(fields []string) string {
	return "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n" + strings.Join(fields, "\n") +
		"\nDate: Sat, 05 Sep 2026 10:12:13 UTC\nArchitectures: all amd64 arm64\nComponents: main\n" +
		"MD5Sum:\n 0123456789abcdef0123456789abcdef      100 main/binary-arm64/Packages\n" +
		"SHA256:\n 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef      100 main/binary-arm64/Packages\n" +
		"-----BEGIN PGP SIGNATURE-----\n\niQIzBAEBCgAdFiEE\n-----END PGP SIGNATURE-----\n"
}

// offered is one stanza of a Packages file, with the fields in the order
// Debian's own lists have them.
func offered(name, version, arch string) string {
	return "Package: " + name + "\nSource: something\nVersion: " + version +
		"\nInstalled-Size: 1234\nMaintainer: A Person <person@example.com>\nArchitecture: " + arch +
		"\nDepends: libc6 (>= 2.36)\nDescription: a package\n with a second line\nFilename: pool/main/x/" + name + ".deb\n"
}

// archive puts one archive into apt's folder, its InRelease and one list,
// and returns the list's path under the root.
func (tr *pkgTree) archive(mirror string, fields []string, stanzas ...string) string {
	tr.t.Helper()
	tr.file(listsDir+mirror+"_InRelease", inRelease(fields))
	list := listsDir + mirror + "_main_binary-arm64_Packages"
	tr.file(list, strings.Join(stanzas, "\n"))
	return list
}

// debianLists is a Debian 12 host's three own archives. The release offers
// one version of OpenSSH and the security archive a newer one.
func debianLists(tr *pkgTree) {
	tr.archive("deb.debian.org_debian_dists_bookworm", debianMain,
		offered("nginx", "1.22.1-9", "arm64"), offered("openssh-server", "1:9.2p1-2", "arm64"),
		offered("zsh", "5.9-4", "arm64"))
	tr.archive("deb.debian.org_debian_dists_bookworm-updates", debianUpdates,
		offered("tzdata", "2026a-0+deb12u1", "all"))
	tr.archive("deb.debian.org_debian-security_dists_bookworm-security", debianSecurity,
		offered("openssh-server", "1:9.2p1-2+deb12u10", "arm64"))
}

// offersFor returns the entry for one package, or fails the test.
func offersFor(t *testing.T, sec *hostdoc.PackagesSection, name string) hostdoc.PackageOffers {
	t.Helper()
	for _, o := range sec.Offers {
		if o.Name == name {
			return o
		}
	}
	t.Fatalf("no offers for %s in %+v", name, sec.Offers)
	return hostdoc.PackageOffers{}
}

// said writes each offer as "archive version", with "!" for a flagged one.
func said(o hostdoc.PackageOffers) string {
	var out []string
	for _, v := range o.Offered {
		line := v.Archive + " " + v.Version
		if v.NotAutomatic || v.ButAutomaticUpgrades {
			line += " !"
		}
		out = append(out, line)
	}
	return strings.Join(out, ", ")
}

func listsVerdict(sec *hostdoc.PackagesSection) hostdoc.SectionStatus {
	return sec.Sources["apt_lists"].Status
}

// countListReads counts how many Packages files a run opens.
func countListReads(t *testing.T) *int {
	t.Helper()
	n := 0
	real := openAptList
	openAptList = func(path string) (*os.File, error) {
		n++
		return real(path)
	}
	t.Cleanup(func() { openAptList = real })
	return &n
}

// ------------------------------------------------- the closed list of words

func TestTheDistributionsOwnArchivesAreSaidInTheirWords(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	sec := tr.collect("ssh.service")
	if got := listsVerdict(sec); got != hostdoc.StatusCollected {
		t.Fatalf("apt_lists reads %q, want collected", got)
	}
	if len(sec.Offers) != 1 {
		t.Fatalf("offers for %d packages, want the one behind the listening service: %+v", len(sec.Offers), sec.Offers)
	}
	o := offersFor(t, sec, "openssh-server")
	if got, want := said(o), "debian 1:9.2p1-2, debian-security 1:9.2p1-2+deb12u10"; got != want {
		t.Errorf("offered %q, want %q", got, want)
	}
	if o.OtherOffers || o.OtherOffersInstalled {
		t.Errorf("no other archive is set up, and the entry says one offers it: %+v", o)
	}
}

func TestAnUpdatesArchiveIsTheDistributionsOwnAndAVersionIsSaidOnce(t *testing.T) {
	tr := sshHost(t)
	tr.archive("deb.debian.org_debian_dists_bookworm", debianMain, offered("openssh-server", "1:9.2p1-2", "arm64"))
	tr.archive("deb.debian.org_debian_dists_bookworm-updates", debianUpdates, offered("openssh-server", "1:9.2p1-2", "arm64"))
	if got, want := said(offersFor(t, tr.collect("ssh.service"), "openssh-server")), "debian 1:9.2p1-2"; got != want {
		t.Errorf("offered %q, want %q once", got, want)
	}
}

func TestUbuntusArchivesAreOneWordAndItsBackportsAreFlagged(t *testing.T) {
	tr := sshHost(t)
	tr.remove("usr/lib/os-release")
	tr.file("usr/lib/os-release", "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n")
	ubuntu := func(suite string, more ...string) []string {
		return append([]string{"Origin: Ubuntu", "Label: Ubuntu", "Suite: " + suite, "Version: 24.04", "Codename: noble"}, more...)
	}
	tr.archive("archive.ubuntu.com_ubuntu_dists_noble", ubuntu("noble"), offered("openssh-server", "1:9.6p1-3ubuntu13", "arm64"))
	tr.archive("archive.ubuntu.com_ubuntu_dists_noble-updates", ubuntu("noble-updates"), offered("openssh-server", "1:9.6p1-3ubuntu13.19", "arm64"))
	tr.archive("security.ubuntu.com_ubuntu_dists_noble-security", ubuntu("noble-security"), offered("openssh-server", "1:9.6p1-3ubuntu13.19", "arm64"))
	tr.archive("archive.ubuntu.com_ubuntu_dists_noble-backports",
		ubuntu("noble-backports", "NotAutomatic: yes", "ButAutomaticUpgrades: yes"), offered("openssh-server", "1:10.0p1-1~bpo24.04.1", "arm64"))
	o := offersFor(t, tr.collect("ssh.service"), "openssh-server")
	want := "ubuntu 1:10.0p1-1~bpo24.04.1 !, ubuntu 1:9.6p1-3ubuntu13, ubuntu 1:9.6p1-3ubuntu13.19"
	if got := said(o); got != want {
		t.Errorf("offered %q, want %q", got, want)
	}
	for _, v := range o.Offered {
		if flagged := v.NotAutomatic && v.ButAutomaticUpgrades; flagged != strings.Contains(v.Version, "bpo") {
			t.Errorf("%s: both flags are %v", v.Version, flagged)
		}
	}
}

// Debian's backports are Debian's own archive, served from Debian's mirrors
// and signed with Debian's archive key, and apt installs nothing from them by
// itself: they carry both flags (backports.debian.org, Instructions, read on
// 2026-10-27, and trixie-backports' own Release file the same day). So they
// are a flagged archive of Debian's, as Ubuntu's backports are of Ubuntu's,
// and not another archive. Until 2026-10-27 they were another archive, and on
// a Debian server with backports in its lists every service a backport
// existed for read "another archive offers this package" and was never
// checked (second big test, 24 October).
func TestDebiansOwnBackportsAreItsFlaggedArchive(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	tr.archive("deb.debian.org_debian_dists_bookworm-backports", debianBackport,
		offered("openssh-server", "1:10.0p1-5~bpo12+1", "arm64"))
	o := offersFor(t, tr.collect("ssh.service"), "openssh-server")
	want := "debian 1:10.0p1-5~bpo12+1 !, debian 1:9.2p1-2, debian-security 1:9.2p1-2+deb12u10"
	if got := said(o); got != want {
		t.Errorf("offered %q, want %q", got, want)
	}
	if o.OtherOffers || o.OtherOffersInstalled {
		t.Errorf("Debian's backports are Debian's own, and the entry says another archive offers it: %+v", o)
	}
	for _, v := range o.Offered {
		if flagged := v.NotAutomatic && v.ButAutomaticUpgrades; flagged != strings.Contains(v.Version, "bpo") {
			t.Errorf("%s: both flags are %v", v.Version, flagged)
		}
	}
}

// Whatever an archive that is not the distribution's own says of itself, and
// whatever it offers, two yes or no facts are all that leaves the host.
func TestAnotherArchiveGivesTwoFactsAndNothingItsOwnerWrote(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	// It offers the very version that is installed, and one of its own.
	tr.archive("apt.acme-internal.example_debian_dists_bookworm", acme,
		offered("openssh-server", "1:9.0p1-1", "arm64"), offered("openssh-server", "1:9.9p9-1+acme7", "arm64"))
	sec := tr.collect("ssh.service")
	o := offersFor(t, sec, "openssh-server")
	if !o.OtherOffers || !o.OtherOffersInstalled {
		t.Errorf("another archive offers the installed version, and the entry says %+v", o)
	}
	if got, want := said(o), "debian 1:9.2p1-2, debian-security 1:9.2p1-2+deb12u10"; got != want {
		t.Errorf("offered %q, want only the distribution's own %q", got, want)
	}
	sent := string(mustMarshal(t, sec))
	for _, theirs := range []string{"Acme", "acme", "internal builds", "9.9p9", "apt.acme", "example", "oldstable", "Debian-Security", "deb.debian.org"} {
		if strings.Contains(sent, theirs) {
			t.Errorf("the report holds %q, which is an archive's own text or address:\n%s", theirs, sent)
		}
	}
}

func TestAnotherArchiveThatOffersOnlyOtherVersionsSaysSo(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	tr.archive("apt.acme-internal.example_debian_dists_bookworm", acme, offered("openssh-server", "1:9.9p9-1+acme7", "arm64"))
	o := offersFor(t, tr.collect("ssh.service"), "openssh-server")
	if !o.OtherOffers || o.OtherOffersInstalled {
		t.Errorf("another archive offers the package and not the installed version, and the entry says %+v", o)
	}
}

// An archive is the distribution's own only when all it says fits. Each of
// these says something close, and each is another archive.
func TestAnArchiveThatDoesNotFitTheClosedListIsAnother(t *testing.T) {
	cases := map[string][]string{
		"debian's backports without either flag": {"Origin: Debian Backports", "Label: Debian Backports",
			"Codename: bookworm-backports"},
		"debian's backports of another release": {"Origin: Debian Backports", "Label: Debian Backports",
			"Codename: trixie-backports", "NotAutomatic: yes", "ButAutomaticUpgrades: yes"},
		"debian's sloppy backports": {"Origin: Debian Backports", "Label: Debian Backports",
			"Codename: bookworm-backports-sloppy", "NotAutomatic: yes", "ButAutomaticUpgrades: yes"},
		"the backports codename with debian's words": {"Origin: Debian", "Label: Debian",
			"Codename: bookworm-backports", "NotAutomatic: yes", "ButAutomaticUpgrades: yes"},
		"the backports origin with debian's label": {"Origin: Debian Backports", "Label: Debian",
			"Codename: bookworm-backports", "NotAutomatic: yes", "ButAutomaticUpgrades: yes"},
		"debian's words, another name": {"Origin: Debian", "Label: Debian", "Codename: trixie"},
		"debian's label on security":   {"Origin: Debian", "Label: Debian", "Codename: bookworm-security"},
		"the security label on main":   {"Origin: Debian", "Label: Debian-Security", "Codename: bookworm"},
		"ubuntu's words on debian":     {"Origin: Ubuntu", "Label: Ubuntu", "Codename: bookworm"},
		"ubuntu's words and release":   {"Origin: Ubuntu", "Label: Ubuntu", "Codename: noble"},
		"lower case":                   {"Origin: debian", "Label: debian", "Codename: bookworm"},
		"a trailing word":              {"Origin: Debian GNU", "Label: Debian", "Codename: bookworm"},
		"no origin":                    {"Label: Debian", "Codename: bookworm"},
		"no codename":                  {"Origin: Debian", "Label: Debian"},
		"an origin said twice":         {"Origin: Debian", "Origin: Acme Corp", "Label: Debian", "Codename: bookworm"},
		"a codename said twice":        {"Origin: Debian", "Label: Debian", "Codename: bookworm", "Codename: bookworm"},
		"no field at all":              {},
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			tr := sshHost(t)
			tr.archive("mirror.example_debian_dists_bookworm", fields, offered("openssh-server", "1:9.0p1-1", "arm64"))
			sec := tr.collect("ssh.service")
			if got := listsVerdict(sec); got != hostdoc.StatusCollected {
				t.Fatalf("apt_lists reads %q, want collected", got)
			}
			o := offersFor(t, sec, "openssh-server")
			if len(o.Offered) != 0 || !o.OtherOffers || !o.OtherOffersInstalled {
				t.Errorf("want no offer of the distribution's and both facts yes, got %+v", o)
			}
		})
	}
}

// A field's name is only a field's name at the start of a line of the signed
// part. What stands in the signed message's armour, inside another field's
// value, in the indented list of files or in the signature says nothing
// about the archive.
func TestOnlyAFieldOfTheSignedPartIsRead(t *testing.T) {
	// The archive says it is Debian's, once, where its fields stand. Every
	// other line here would change the answer if it were read as a field: a
	// second codename in the armour, a flag inside a field's value, a flag
	// in the list of files, and a flag inside the signature. The last line
	// of the list of files names the list, as every archive read does.
	body := "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\nCodename: trixie\n\n" +
		"Origin: Debian\nLabel: Debian\nCodename: bookworm\nDescription: NotAutomatic: yes\n" +
		"MD5Sum:\n 00 1 NotAutomatic: yes\n\tButAutomaticUpgrades: yes\n 00 1 main/binary-arm64/Packages\n" +
		"-----BEGIN PGP SIGNATURE-----\n\nButAutomaticUpgrades: yes\n-----END PGP SIGNATURE-----\n"
	tr := sshHost(t)
	tr.file(listsDir+"deb.debian.org_debian_dists_bookworm_InRelease", body)
	tr.file(listsDir+"deb.debian.org_debian_dists_bookworm_main_binary-arm64_Packages", offered("openssh-server", "1:9.2p1-2", "arm64"))
	o := offersFor(t, tr.collect("ssh.service"), "openssh-server")
	if got, want := said(o), "debian 1:9.2p1-2"; got != want || o.OtherOffers {
		t.Errorf("offered %q and other %v, want %q with no flag and no other archive", got, o.OtherOffers, want)
	}

	// And the other way round: what the archive says where its fields stand
	// is what counts, whatever stands after them.
	theirs := "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Acme Corp\nLabel: Acme\nCodename: bookworm\n" +
		"MD5Sum:\n 00 1 main/binary-arm64/Packages\n-----BEGIN PGP SIGNATURE-----\n\nOrigin: Debian\nLabel: Debian\n-----END PGP SIGNATURE-----\n"
	tr = sshHost(t)
	tr.file(listsDir+"mirror.example_debian_dists_bookworm_InRelease", theirs)
	tr.file(listsDir+"mirror.example_debian_dists_bookworm_main_binary-arm64_Packages", offered("openssh-server", "1:9.0p1-1", "arm64"))
	o = offersFor(t, tr.collect("ssh.service"), "openssh-server")
	if len(o.Offered) != 0 || !o.OtherOffers {
		t.Errorf("the archive says Acme Corp where its fields stand, and was read as %+v", o)
	}
}

// Nothing fixes the order of an archive's fields, so a flag is read wherever
// it stands: after the list of files as well as before it. A flag that was
// missed would make a backport look like an update.
func TestAFlagAfterTheListOfFilesIsRead(t *testing.T) {
	var files strings.Builder
	for i := 0; i < 4000; i++ {
		files.WriteString(" 0123456789abcdef0123456789abcdef 1234567 main/binary-arm64/Packages.xz\n")
	}
	// The list itself is named once, after four thousand lines that name
	// other files, so it is found only by a reader that reads them all.
	files.WriteString(" 0123456789abcdef0123456789abcdef 7654321 main/binary-arm64/Packages\n")
	body := "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Debian\nLabel: Debian\nCodename: bookworm\n" +
		"MD5Sum:\n" + files.String() + "NotAutomatic: yes\nSHA256:\n" + files.String() + "ButAutomaticUpgrades: yes\n" +
		"-----BEGIN PGP SIGNATURE-----\n\niQIzBAEBCgAdFiEE\n-----END PGP SIGNATURE-----\n"
	tr := sshHost(t)
	tr.file(listsDir+"deb.debian.org_debian_dists_bookworm_InRelease", body)
	tr.file(listsDir+"deb.debian.org_debian_dists_bookworm_main_binary-arm64_Packages", offered("openssh-server", "1:9.2p1-2", "arm64"))
	o := offersFor(t, tr.collect("ssh.service"), "openssh-server")
	if len(o.Offered) != 1 || !o.Offered[0].NotAutomatic || !o.Offered[0].ButAutomaticUpgrades {
		t.Errorf("both flags stand after a list of files, and the offer reads %+v", o.Offered)
	}
}

// A Release file past its cap is not read by halves.
func TestAReleaseFilePastItsCapIsNotRead(t *testing.T) {
	maxReleaseBytes = 256
	t.Cleanup(func() { maxReleaseBytes = 16 << 20 })
	tr := sshHost(t)
	debianLists(tr)
	sec := tr.collect("ssh.service")
	if got := listsVerdict(sec); got != hostdoc.StatusReadError {
		t.Errorf("apt_lists reads %q, want read_error", got)
	}
	if len(sec.Offers) != 0 {
		t.Errorf("offers from an archive whose own word was not read whole: %+v", sec.Offers)
	}
}

// An archive with a Release file and no InRelease is read the same way.
func TestAnArchiveWithAReleaseFileAndNoInReleaseIsRead(t *testing.T) {
	tr := sshHost(t)
	tr.file(listsDir+"deb.debian.org_debian_dists_bookworm_Release", strings.Join(debianMain, "\n")+"\nMD5Sum:\n 00 1 main/binary-arm64/Packages\n")
	tr.file(listsDir+"deb.debian.org_debian_dists_bookworm_main_binary-arm64_Packages", offered("openssh-server", "1:9.2p1-2", "arm64"))
	if got, want := said(offersFor(t, tr.collect("ssh.service"), "openssh-server")), "debian 1:9.2p1-2"; got != want {
		t.Errorf("offered %q, want %q", got, want)
	}
}

// ------------------------------------------------------------ what is read

func TestAStanzaForAnotherArchitectureIsNoOffer(t *testing.T) {
	tr := sshHost(t)
	tr.archive("deb.debian.org_debian_dists_bookworm", debianMain,
		offered("openssh-server", "1:9.2p1-2+amd64only", "amd64"), offered("openssh-server", "1:9.2p1-2", "arm64"))
	tr.archive("deb.debian.org_debian_dists_bookworm-updates", debianUpdates, offered("openssh-server", "1:9.2p1-3", "all"))
	if got, want := said(offersFor(t, tr.collect("ssh.service"), "openssh-server")), "debian 1:9.2p1-2, debian 1:9.2p1-3"; got != want {
		t.Errorf("offered %q, want the host's own architecture and all: %q", got, want)
	}
}

// A line longer than the reader's buffer is one line. Its rest is not the
// start of a field, whatever it holds.
func TestALineLongerThanTheBufferIsOneLine(t *testing.T) {
	tr := sshHost(t)
	long := strings.Repeat("x", 300*1024)
	stanza := "Package: openssh-server\nVersion: 1:9.2p1-2\nArchitecture: arm64\nDescription: " + long +
		"\nVersion: 1:99.0-1\nPackage: openssh-server\n"
	// The second Version line above is a field of the same stanza, said
	// twice, and the list is then not one this reader understands.
	tr.archive("deb.debian.org_debian_dists_bookworm", debianMain, stanza)
	if got := listsVerdict(tr.collect("ssh.service")); got != hostdoc.StatusReadError {
		t.Errorf("a stanza that says its version twice reads %q, want read_error", got)
	}
	tr2 := sshHost(t)
	tr2.archive("deb.debian.org_debian_dists_bookworm", debianMain,
		"Package: openssh-server\nVersion: 1:9.2p1-2\nArchitecture: arm64\nDescription: "+long+"Version: 1:99.0-1\n")
	if got, want := said(offersFor(t, tr2.collect("ssh.service"), "openssh-server")), "debian 1:9.2p1-2"; got != want {
		t.Errorf("offered %q, want %q: the long line's tail is not a field", got, want)
	}
}

func TestMoreVersionsThanTheCapAreCutAndSaidSo(t *testing.T) {
	tr := sshHost(t)
	var stanzas []string
	for i := 0; i < hostdoc.MaxOffersPerPackage+3; i++ {
		stanzas = append(stanzas, offered("openssh-server", "1:9.2p1-"+string(rune('a'+i)), "arm64"))
	}
	tr.archive("deb.debian.org_debian_dists_bookworm", debianMain, stanzas...)
	o := offersFor(t, tr.collect("ssh.service"), "openssh-server")
	if len(o.Offered) != hostdoc.MaxOffersPerPackage || !o.OfferedCut {
		t.Errorf("%d offers, cut %v, want %d and cut", len(o.Offered), o.OfferedCut, hostdoc.MaxOffersPerPackage)
	}
}

// ----------------------------------------------- a read that is not complete

// Offers are a claim about every list on the host. When one list was not
// read whole there is no such claim, and none is made.
func TestAListThatWasNotReadWholeLeavesNoOffers(t *testing.T) {
	cases := map[string]func(tr *pkgTree, list string){
		"a compressed list beside it": func(tr *pkgTree, _ string) {
			tr.file(listsDir+"deb.debian.org_debian_dists_bookworm_contrib_binary-arm64_Packages.lz4", "\x04\x22\x4d\x18")
		},
		"a version that is no version": func(tr *pkgTree, list string) {
			tr.file(list, offered("openssh-server", "1:9.2p1-2 <b>hello</b>", "arm64"))
		},
		"a stanza with no version": func(tr *pkgTree, list string) {
			tr.file(list, "Package: openssh-server\nArchitecture: arm64\n")
		},
		"a version said twice": func(tr *pkgTree, list string) {
			tr.file(list, "Package: openssh-server\nVersion: 1:9.2p1-2\nVersion: 1:99.0-1\nArchitecture: arm64\n")
		},
		"an architecture said twice": func(tr *pkgTree, list string) {
			tr.file(list, "Package: openssh-server\nVersion: 1:9.2p1-2\nArchitecture: amd64\nArchitecture: arm64\n")
		},
		"two names in one stanza": func(tr *pkgTree, list string) {
			tr.file(list, "Package: zsh\nPackage: openssh-server\nVersion: 1:9.2p1-2\nArchitecture: arm64\n")
		},
		"a stanza with no architecture": func(tr *pkgTree, list string) {
			tr.file(list, "Package: openssh-server\nVersion: 1:9.2p1-2\n")
		},
		"a list past its cap": func(tr *pkgTree, list string) {
			maxAptListBytes = 64
			tr.t.Cleanup(func() { maxAptListBytes = 512 << 20 })
		},
		"a list that is a directory": func(tr *pkgTree, list string) {
			tr.remove(list)
			tr.dir(list)
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			tr := sshHost(t)
			list := tr.archive("deb.debian.org_debian_dists_bookworm", debianMain, offered("openssh-server", "1:9.2p1-2", "arm64"))
			breakIt(tr, list)
			sec := tr.collect("ssh.service")
			if got := listsVerdict(sec); got != hostdoc.StatusReadError {
				t.Errorf("apt_lists reads %q, want read_error", got)
			}
			if len(sec.Offers) != 0 {
				t.Errorf("offers from lists that were not read whole: %+v", sec.Offers)
			}
			if strings.Contains(string(mustMarshal(t, sec)), "hello") {
				t.Error("text out of a list is in the report")
			}
			// The units are dpkg's and are there all the same.
			if len(sec.Units) != 1 || sec.Status != hostdoc.StatusCollected {
				t.Errorf("the units went with the lists: %+v", sec)
			}
		})
	}
}

// apt may replace a list while it is being read. What was read is then not
// the list that is there, so the read is not complete and nothing is kept.
func TestAListReplacedWhileItWasReadIsNotBelieved(t *testing.T) {
	tr := sshHost(t)
	list := tr.archive("deb.debian.org_debian_dists_bookworm", debianMain, offered("openssh-server", "1:9.2p1-2", "arm64"))
	real := openAptList
	openAptList = func(path string) (*os.File, error) {
		f, err := real(path)
		// The list grows by a package between the open and the end of the
		// read.
		tr.file(list, offered("openssh-server", "1:9.2p1-2", "arm64")+"\n"+offered("zsh", "5.9-4", "arm64"))
		return f, err
	}
	t.Cleanup(func() { openAptList = real })
	sec, kept := CollectPackagesKeeping(tr.root, []string{"ssh.service"}, nil)
	mustMarshal(t, sec)
	if got := listsVerdict(sec); got != hostdoc.StatusReadError {
		t.Errorf("apt_lists reads %q, want read_error", got)
	}
	if len(sec.Offers) != 0 || len(kept) != 0 {
		t.Errorf("a list replaced while it was read gave offers %+v and kept %q", sec.Offers, kept)
	}
}

func TestAListThatMayNotBeReadSaysPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its mode")
	}
	tr := sshHost(t)
	list := tr.archive("deb.debian.org_debian_dists_bookworm", debianMain, offered("openssh-server", "1:9.2p1-2", "arm64"))
	tr.deny(list)
	sec := tr.collect("ssh.service")
	if got := listsVerdict(sec); got != hostdoc.StatusPermissionDenied {
		t.Errorf("apt_lists reads %q, want permission_denied", got)
	}
	if len(sec.Offers) != 0 {
		t.Errorf("offers from a list that was not read: %+v", sec.Offers)
	}
}

func TestAHostWithNoListsFolderReadsNotPresent(t *testing.T) {
	sec := sshHost(t).collect("ssh.service")
	if got := listsVerdict(sec); got != hostdoc.StatusNotPresent {
		t.Errorf("apt_lists reads %q, want not_present", got)
	}
	if len(sec.Offers) != 0 {
		t.Errorf("offers with no folder to read: %+v", sec.Offers)
	}
}

// A folder that holds no list is a read that is complete: every list in it
// was read, and they offer nothing. apt's own lock file and its partial
// folder are not lists.
func TestAFolderWithNoListOffersNothingAndIsComplete(t *testing.T) {
	tr := sshHost(t)
	tr.file(listsDir+"lock", "")
	tr.dir(listsDir + "partial")
	tr.dir(listsDir + "auxfiles")
	tr.file(listsDir+"deb.debian.org_debian_dists_bookworm_InRelease", inRelease(debianMain))
	tr.file(listsDir+"deb.debian.org_debian_dists_bookworm_main_i18n_Translation-en", "Package: openssh-server\nVersion: 1:1-1\n")
	sec := tr.collect("ssh.service")
	if got := listsVerdict(sec); got != hostdoc.StatusCollected {
		t.Fatalf("apt_lists reads %q, want collected", got)
	}
	o := offersFor(t, sec, "openssh-server")
	if len(o.Offered) != 0 || o.OtherOffers || o.OtherOffersInstalled {
		t.Errorf("no list offers anything, and the entry says %+v", o)
	}
}

// With no package to ask about nothing is read: a hundred megabytes of lists
// for no question would be the cost with none of the answer.
func TestWithNoPackageBehindAListeningServiceTheListsAreNotRead(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	reads := countListReads(t)
	sec := tr.collect()
	if *reads != 0 {
		t.Errorf("%d lists read for no package", *reads)
	}
	if got := listsVerdict(sec); got != hostdoc.StatusNotCollected {
		t.Errorf("apt_lists reads %q, want not_collected", got)
	}
	if len(sec.Offers) != 0 {
		t.Errorf("offers for no package: %+v", sec.Offers)
	}
}

func TestTheSameListsGiveTheSameBytes(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	tr.archive("apt.acme-internal.example_debian_dists_bookworm", acme, offered("openssh-server", "1:9.0p1-1", "arm64"))
	first := mustMarshal(t, tr.collect("ssh.service"))
	for i := 0; i < 5; i++ {
		if again := mustMarshal(t, tr.collect("ssh.service")); !bytes.Equal(first, again) {
			t.Fatalf("run %d differs from the first:\n%s\n%s", i, first, again)
		}
	}
}

// ---------------------------------------------------- what the agent keeps
//
// The agent's process ends after each report, so what it read is kept as
// bytes its caller writes beside the state file, and handed back the next
// time. A list is opened again only when it changed.

// keeping runs the collector with what the last run kept, and returns the
// section, what to keep now, and how many lists were opened.
func keeping(t *testing.T, tr *pkgTree, kept []byte, units ...string) (*hostdoc.PackagesSection, []byte, int) {
	t.Helper()
	reads := countListReads(t)
	sec, keep := CollectPackagesKeeping(tr.root, units, kept)
	mustMarshal(t, sec)
	return sec, keep, *reads
}

func TestAListThatDidNotChangeIsNotReadAgain(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	first, kept, reads := keeping(t, tr, nil, "ssh.service")
	if reads != 3 {
		t.Fatalf("the first run opened %d lists, want all 3", reads)
	}
	if len(kept) == 0 {
		t.Fatal("the first run kept nothing")
	}
	second, keptAgain, reads := keeping(t, tr, kept, "ssh.service")
	if reads != 0 {
		t.Errorf("the second run opened %d lists, and none had changed", reads)
	}
	if a, b := mustMarshal(t, first), mustMarshal(t, second); !bytes.Equal(a, b) {
		t.Errorf("the kept answer is not the read one:\n%s\n%s", a, b)
	}
	if !bytes.Equal(kept, keptAgain) {
		t.Errorf("what is kept changed with nothing read:\n%s\n%s", kept, keptAgain)
	}
}

func TestAListWhoseSizeOrTimeChangedIsReadAgain(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	security := filepath.Join(tr.root, listsDir+"deb.debian.org_debian-security_dists_bookworm-security_main_binary-arm64_Packages")
	_, kept, _ := keeping(t, tr, nil, "ssh.service")
	before, err := os.Stat(security)
	if err != nil {
		t.Fatal(err)
	}

	// Its size changed and its time did not.
	tr.file(listsDir+"deb.debian.org_debian-security_dists_bookworm-security_main_binary-arm64_Packages",
		offered("openssh-server", "1:9.2p1-2+deb12u9", "arm64"))
	if err := os.Chtimes(security, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(security)
	if after.Size() == before.Size() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("the fixture did not change the size alone: %d to %d bytes, %v to %v", before.Size(), after.Size(), before.ModTime(), after.ModTime())
	}
	sec, kept, reads := keeping(t, tr, kept, "ssh.service")
	if reads != 1 {
		t.Errorf("%d lists opened after one changed its size, want 1", reads)
	}
	if got, want := said(offersFor(t, sec, "openssh-server")), "debian 1:9.2p1-2, debian-security 1:9.2p1-2+deb12u9"; got != want {
		t.Errorf("offered %q, want the new list's %q", got, want)
	}

	// Its time changed and its size did not: another version of one length.
	tr.file(listsDir+"deb.debian.org_debian-security_dists_bookworm-security_main_binary-arm64_Packages",
		offered("openssh-server", "1:9.2p1-2+deb12u8", "arm64"))
	later := before.ModTime().Add(time.Hour)
	if err := os.Chtimes(security, later, later); err != nil {
		t.Fatal(err)
	}
	now, _ := os.Stat(security)
	if now.Size() != after.Size() {
		t.Fatalf("the fixture changed the size too: %d to %d bytes", after.Size(), now.Size())
	}
	sec, _, reads = keeping(t, tr, kept, "ssh.service")
	if reads != 1 {
		t.Errorf("%d lists opened after one changed its time, want 1", reads)
	}
	if got, want := said(offersFor(t, sec, "openssh-server")), "debian 1:9.2p1-2, debian-security 1:9.2p1-2+deb12u8"; got != want {
		t.Errorf("offered %q, want the new list's %q", got, want)
	}
}

// A list that is gone is gone from the answer, and a new one is read.
func TestAListThatCameOrWentIsNotAnsweredFromWhatWasKept(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	_, kept, _ := keeping(t, tr, nil, "ssh.service")
	tr.remove(listsDir + "deb.debian.org_debian-security_dists_bookworm-security_main_binary-arm64_Packages")
	tr.archive("deb.debian.org_debian_dists_bookworm-proposed-updates",
		[]string{"Origin: Debian", "Label: Debian", "Codename: bookworm-proposed-updates"},
		offered("openssh-server", "1:9.2p1-2+deb12u13", "arm64"))
	sec, _, reads := keeping(t, tr, kept, "ssh.service")
	if reads != 1 {
		t.Errorf("%d lists opened, want only the new one", reads)
	}
	o := offersFor(t, sec, "openssh-server")
	if got, want := said(o), "debian 1:9.2p1-2"; got != want {
		t.Errorf("offered %q, want %q: the list that went is not offered", got, want)
	}
	if !o.OtherOffers {
		t.Errorf("the new archive is not one of the three and offers the package: %+v", o)
	}
}

func TestAPackageNotAskedForBeforeIsReadFromTheLists(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	tr.unitFile("nginx.service", "ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'")
	tr.file("usr/sbin/nginx", elfHead)
	tr.pkg("nginx", "Package: nginx\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.22.1-8",
		"/lib/systemd/system/nginx.service", "/usr/sbin/nginx")
	_, kept, _ := keeping(t, tr, nil, "ssh.service")

	sec, keptBoth, reads := keeping(t, tr, kept, "nginx.service", "ssh.service")
	if reads != 3 {
		t.Errorf("%d lists opened for a package that was not asked for before, want all 3", reads)
	}
	if got, want := said(offersFor(t, sec, "nginx")), "debian 1.22.1-9"; got != want {
		t.Errorf("nginx offered %q, want %q", got, want)
	}
	if got, want := said(offersFor(t, sec, "openssh-server")), "debian 1:9.2p1-2, debian-security 1:9.2p1-2+deb12u10"; got != want {
		t.Errorf("openssh-server offered %q, want %q", got, want)
	}
	// And a package fewer is answered from what is kept, with nothing read.
	sec, _, reads = keeping(t, tr, keptBoth, "ssh.service")
	if reads != 0 {
		t.Errorf("%d lists opened to ask about fewer packages", reads)
	}
	if len(sec.Offers) != 1 || sec.Offers[0].Name != "openssh-server" {
		t.Errorf("offers for a package no listening service has: %+v", sec.Offers)
	}
}

// What is kept is a file on a disk, and anybody who can write there can
// write into it. So it is believed only where it is exactly what this reader
// writes, and every version out of it is held to a version's shape like one
// out of a list. Anything else and the lists are read as if nothing was kept.
func TestAKeptFileThatIsNotUnderstoodIsNeverTrusted(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	honest, kept, _ := keeping(t, tr, nil, "ssh.service")
	want := mustMarshal(t, honest)
	edit := func(old, new string) []byte {
		if !bytes.Contains(kept, []byte(old)) {
			t.Fatalf("what is kept holds no %q to change:\n%s", old, kept)
		}
		return bytes.Replace(kept, []byte(old), []byte(new), 1)
	}
	cases := map[string][]byte{
		"not json":                       []byte("Package: openssh-server\nVersion: 1:99-1\n"),
		"an empty file":                  {},
		"an empty object":                []byte("{}"),
		"a list where an object belongs": []byte("[]"),
		"half of it":                     kept[:len(kept)/2],
		"another version of the file":    edit(`"kept_version":1`, `"kept_version":2`),
		"a version that is text":         edit(`"1:9.2p1-2+deb12u10"`, `"1:9.2p1-2 <b>hello</b>"`),
		"a version with a newline":       edit(`"1:9.2p1-2+deb12u10"`, `"1:9.2p1-2\nhello"`),
		"a name that is text":            edit(`"name":"openssh-server"`, `"name":"hello world"`),
		"an architecture that is text":   edit(`"architecture":"arm64"`, `"architecture":"hello world"`),
		"a field it does not know":       edit(`"kept_version":1`, `"kept_version":1,"hello":"world"`),
		"something after it":             append(append([]byte{}, kept...), []byte(`{"hello":1}`)...),
	}
	for name, written := range cases {
		t.Run(name, func(t *testing.T) {
			sec, keep, reads := keeping(t, tr, written, "ssh.service")
			if reads != 3 {
				t.Errorf("%d lists opened, want all 3 read again", reads)
			}
			got := mustMarshal(t, sec)
			if !bytes.Equal(got, want) {
				t.Errorf("the report is not the one the lists give:\n%s\n%s", got, want)
			}
			if bytes.Contains(got, []byte("hello")) {
				t.Error("text out of the kept file is in the report")
			}
			if !bytes.Equal(keep, kept) {
				t.Errorf("what is kept after it is not what a clean read keeps:\n%s\n%s", keep, kept)
			}
		})
	}
}

// What a kept file can still do, said and held: one that is exactly the
// reader's own shape and names a list's true size and time is believed, and
// its versions go out. They are versions in shape and nothing else, and
// whoever can write that file can write the agent's whole state.
func TestAKeptFileInTheReadersOwnShapeIsBelievedAndSendsOnlyVersions(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	_, kept, _ := keeping(t, tr, nil, "ssh.service")
	forged := bytes.Replace(kept, []byte(`"1:9.2p1-2+deb12u10"`), []byte(`"1:9.2p1-2+deb12u99"`), 1)
	sec, _, reads := keeping(t, tr, forged, "ssh.service")
	if reads != 0 {
		t.Fatalf("%d lists opened, and the kept file names each list's size and time", reads)
	}
	for _, v := range offersFor(t, sec, "openssh-server").Offered {
		if !hostdoc.PackageVersion(v.Version) {
			t.Errorf("%q went out and has not the shape of a version", v.Version)
		}
	}
}

// Nothing is kept from a read that was not complete, so the next run reads
// again and never answers from half.
func TestNothingIsKeptFromAReadThatWasNotComplete(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	tr.file(listsDir+"deb.debian.org_debian_dists_bookworm_contrib_binary-arm64_Packages.xz", "\xfd7zXZ")
	sec, kept, _ := keeping(t, tr, nil, "ssh.service")
	if got := listsVerdict(sec); got != hostdoc.StatusReadError {
		t.Fatalf("apt_lists reads %q, want read_error", got)
	}
	if len(kept) != 0 {
		t.Errorf("a read that was not complete kept:\n%s", kept)
	}
}

// What is kept names the lists, their sizes and times, and the versions of
// the packages asked for. No other package of a list, and none of a stanza's
// other fields.
func TestWhatIsKeptHoldsOnlyTheAskedPackagesVersions(t *testing.T) {
	tr := sshHost(t)
	debianLists(tr)
	_, kept, _ := keeping(t, tr, nil, "ssh.service")
	for _, notAsked := range []string{"zsh", "tzdata", "nginx", "person@example.com", "libc6", "pool/main", "Origin", "Debian"} {
		if bytes.Contains(kept, []byte(notAsked)) {
			t.Errorf("what is kept holds %q:\n%s", notAsked, kept)
		}
	}
	if !bytes.Contains(kept, []byte("openssh-server")) || !bytes.Contains(kept, []byte("1:9.2p1-2+deb12u10")) {
		t.Errorf("what is kept does not hold the asked package's version:\n%s", kept)
	}
}
