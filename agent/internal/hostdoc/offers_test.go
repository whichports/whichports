package hostdoc

import (
	"encoding/json"
	"strings"
	"testing"
)

// What a host's own apt lists offer for a package: what the marshaller
// refuses, what it carries through, and how large it can ever be.

func goodOffers() PackageOffers {
	return PackageOffers{
		Name: "openssh-server",
		Offered: []Offer{
			{Version: "1:9.2p1-2+deb12u10", Archive: "debian"},
			{Version: "1:9.2p1-2+deb12u9", Archive: "debian-security"},
		},
	}
}

func packagesWithOffers() *PackagesSection {
	p := goodPackages()
	p.Sources["apt_lists"] = Section{Status: StatusCollected}
	p.Offers = []PackageOffers{goodOffers()}
	return p
}

func TestGoodOffersRoundTrip(t *testing.T) {
	p := packagesWithOffers()
	p.Offers[0].OtherOffers = true
	b, err := marshalPackages(p)
	if err != nil {
		t.Fatal(err)
	}
	var back Document
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	got := back.Packages.Offers[0]
	if got.Name != "openssh-server" || len(got.Offered) != 2 || got.Offered[1].Archive != "debian-security" || !got.OtherOffers {
		t.Errorf("round trip lost a field: %+v", got)
	}
	// Each of the four yes or no facts is written when it is no, so a reader
	// never has to guess what an absent field meant.
	for _, fact := range []string{`"not_automatic": false`, `"but_automatic_upgrades": false`,
		`"other_offers_installed": false`} {
		if !strings.Contains(string(b), fact) {
			t.Errorf("%s was left out:\n%s", fact, b)
		}
	}
}

func TestAnOldDocumentWithoutOffersStillMarshals(t *testing.T) {
	b, err := marshalPackages(goodPackages())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "offers") || strings.Contains(string(b), "apt_lists") {
		t.Errorf("a section with no offers names them:\n%s", b)
	}
}

// The word for an archive is one of three. Everything else an archive says
// of itself is text its owner wrote, and stays on the host (SI-8).
func TestTheArchiveWordsAreOneClosedList(t *testing.T) {
	want := []string{"debian", "debian-security", "ubuntu"}
	if strings.Join(OfferArchives, " ") != strings.Join(want, " ") {
		t.Fatalf("the archive words are %v, want exactly %v", OfferArchives, want)
	}
	for _, word := range want {
		p := packagesWithOffers()
		p.Offers[0].Offered = []Offer{{Version: "1.0-1", Archive: word}}
		if _, err := marshalPackages(p); err != nil {
			t.Errorf("archive %q refused: %v", word, err)
		}
	}
}

func TestMarshalRefusesWhatOffersMayNotCarry(t *testing.T) {
	long := func(n int) string { return strings.Repeat("1", n) }
	cases := map[string]func(p *PackagesSection){
		"an archive's own name":         func(p *PackagesSection) { p.Offers[0].Offered[0].Archive = "Acme Internal" },
		"the word other":                func(p *PackagesSection) { p.Offers[0].Offered[0].Archive = "other" },
		"an empty archive":              func(p *PackagesSection) { p.Offers[0].Offered[0].Archive = "" },
		"an empty version":              func(p *PackagesSection) { p.Offers[0].Offered[0].Version = "" },
		"a version with a space":        func(p *PackagesSection) { p.Offers[0].Offered[0].Version = "1.0 hello" },
		"a version with a slash":        func(p *PackagesSection) { p.Offers[0].Offered[0].Version = "1.0/acme" },
		"a version with a control byte": func(p *PackagesSection) { p.Offers[0].Offered[0].Version = "1.0\x1b[31m" },
		"a version that starts as text": func(p *PackagesSection) { p.Offers[0].Offered[0].Version = "-1.0" },
		"a version past its cap":        func(p *PackagesSection) { p.Offers[0].Offered[0].Version = long(MaxPackageFieldLen + 1) },
		"a package with no name":        func(p *PackagesSection) { p.Offers[0].Name = "" },
		"a package name with a space":   func(p *PackagesSection) { p.Offers[0].Name = "open ssh" },
		"packages out of order":         func(p *PackagesSection) { o := goodOffers(); o.Name = "a"; p.Offers = append(p.Offers, o) },
		"a package twice":               func(p *PackagesSection) { p.Offers = append(p.Offers, goodOffers()) },
		"an offer twice":                func(p *PackagesSection) { p.Offers[0].Offered[1] = p.Offers[0].Offered[0] },
		"offers out of order":           func(p *PackagesSection) { o := p.Offers[0].Offered; o[0], o[1] = o[1], o[0] },
		"the installed one of no other": func(p *PackagesSection) { p.Offers[0].OtherOffersInstalled = true },
		"offers from lists not read":    func(p *PackagesSection) { delete(p.Sources, "apt_lists") },
		"offers from lists half read": func(p *PackagesSection) {
			p.Sources["apt_lists"] = Section{Status: StatusReadError, Cause: CauseParseFailed}
		},
		"offers from lists that are not": func(p *PackagesSection) { p.Sources["apt_lists"] = Section{Status: StatusNotPresent} },
		"cut offers from lists not read": func(p *PackagesSection) { p.Offers = nil; p.OffersCut = true; delete(p.Sources, "apt_lists") },
		"more offers than the cap for one": func(p *PackagesSection) {
			p.Offers[0].Offered = nil
			for i := 0; i <= MaxOffersPerPackage; i++ {
				p.Offers[0].Offered = append(p.Offers[0].Offered, Offer{Version: "1.0-" + twoDigits(i), Archive: "debian"})
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := packagesWithOffers()
			mutate(p)
			if _, err := marshalPackages(p); err == nil {
				t.Fatal("Marshal must refuse it")
			}
		})
	}
}

func twoDigits(i int) string {
	return strings.Repeat("0", 2-len(itoa(i))) + itoa(i)
}

func TestTooManyPackagesWithOffersAreRefused(t *testing.T) {
	p := packagesWithOffers()
	p.Offers = nil
	for i := 0; i <= MaxOfferPackages; i++ {
		o := goodOffers()
		o.Name = "p" + strings.Repeat("0", 4-len(itoa(i))) + itoa(i)
		p.Offers = append(p.Offers, o)
	}
	if _, err := marshalPackages(p); err == nil {
		t.Fatal("one package past the cap must be refused")
	}
	p.Offers = p.Offers[:MaxOfferPackages]
	if _, err := marshalPackages(p); err != nil {
		t.Fatalf("the cap itself must be accepted: %v", err)
	}
}

// A version is said only when it has the shape deb-version(7) gives one:
// letters, digits, and the marks ". + - ~", with ":" after an epoch, starting
// with a letter or a digit. The same function holds a version read from a
// list and one read back from the file the agent keeps.
func TestAVersionHasTheShapeOfAVersion(t *testing.T) {
	for _, good := range []string{"1:9.2p1-2+deb12u10", "1.22.1-9", "1:11.4.13+maria~deb12",
		"8.14.1-2+deb13u2~bpo13+1", "7.3-pve1", "2", "0.9.5+dfsg-0ubuntu1+esm1"} {
		if !PackageVersion(good) {
			t.Errorf("%q is a version and was refused", good)
		}
	}
	for _, bad := range []string{"", " ", "1.0 ", "1.0\n", "1.0;rm", "1.0/2", "(1.0)", "1.0=2", "+1", "~1",
		"1.0\x00", "1.0é", "<script>", "$(id)", strings.Repeat("1", MaxPackageFieldLen+1)} {
		if PackageVersion(bad) {
			t.Errorf("%q is no version and was accepted", bad)
		}
	}
}

// With every cap of the offers reached on top of every cap of the units, the
// section must still leave room under the ingest's limit.
func TestTheLargestPossibleOffersStayUnderTheIngestLimit(t *testing.T) {
	p := packagesWithOffers()
	p.Offers, p.OffersCut = nil, true
	for i := 0; i < MaxOfferPackages; i++ {
		entry := PackageOffers{
			Name:       strings.Repeat("p", MaxPackageFieldLen-4) + strings.Repeat("0", 4-len(itoa(i))) + itoa(i),
			OfferedCut: true, OtherOffers: true, OtherOffersInstalled: true}
		for j := 0; j < MaxOffersPerPackage; j++ {
			entry.Offered = append(entry.Offered, Offer{
				Version: strings.Repeat("9", MaxPackageFieldLen-2) + twoDigits(j),
				Archive: "debian-security", NotAutomatic: true, ButAutomaticUpgrades: true})
		}
		p.Offers = append(p.Offers, entry)
	}
	b, err := marshalPackages(p)
	if err != nil {
		t.Fatal(err)
	}
	// The units' own largest is 1,887,781 bytes
	// (TestTheLargestPossibleSectionStaysWellUnderTheIngestLimit, 2026-10-07),
	// so the two together must stay under half of the limit.
	const largestUnits = 1887781
	if len(b)+largestUnits > ingestLimit/2 {
		t.Errorf("the largest offers are %d bytes, and with the largest units more than half of the ingest's %d", len(b), ingestLimit)
	}
	t.Logf("the largest possible offers marshal to %d bytes", len(b))
}
