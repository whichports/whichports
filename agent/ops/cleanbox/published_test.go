package cleanbox

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestPublishedInstaller runs the exact line the page gives a stranger:
//
//	curl -fsSL https://get.whichports.com | sh
//
// on a box with nothing on it, in both families, against the real published
// repository. Nothing here is rewritten and nothing is served locally.
//
// It is opt-in because it needs the network, and the reason it is opt-in rather
// than part of the gate is the same reason the rest of this package is offline:
// a check that fails when a CDN hiccups teaches people to ignore failures. Run
// it before a release and after a publish, which are the two moments the answer
// changes:
//
//	cd agent && WHICHPORTS_CLEANBOX_ONLINE=1 go test -v -run Published ./ops/cleanbox/
//
// What only this test can establish, and the offline tests cannot:
//   - get.whichports.com serves the installer, the key and the packages over
//     https, so the path an operator actually walks works end to end
//   - the fingerprint pinned in install.sh is the key that signs what is
//     published, not merely the key committed next to it in this repository
//   - the version in the published repository is the version of the latest tag,
//     so a publish that did not reach the server is visible
func TestPublishedInstaller(t *testing.T) {
	if os.Getenv("WHICHPORTS_CLEANBOX_ONLINE") == "" {
		t.Skip("the published-channel test needs the network. Run: " +
			"WHICHPORTS_CLEANBOX_ONLINE=1 go test -run Published ./ops/cleanbox/")
	}
	f := requireFixture(t)

	// The version the repository is expected to be serving. publish.sh tags the
	// commit it publishes, so the newest tag is what should be live.
	tag, err := exec.Command("git", "describe", "--tags", "--abbrev=0", "--match", "v*").Output()
	if err != nil {
		t.Fatalf("reading the newest v* tag: %v", err)
	}
	wantVersion := strings.TrimPrefix(strings.TrimSpace(string(tag)), "v")
	if wantVersion == "" {
		t.Fatal("no v* tag in this checkout, so there is nothing to compare the published version with")
	}

	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			// An empty served directory: nothing local is mounted, so anything
			// the installer reads has to have come off the network.
			served := t.TempDir()
			b := startBox(t, fam, fam.image, served)

			out, err := b.sh("curl -fsSL https://get.whichports.com | sh")
			if err != nil {
				t.Fatalf("the published one-liner failed on %s: %v\n%s", fam.name, err, out)
			}
			// The installer prints the fingerprint it accepted, and it only
			// accepts the one pinned in the script, so this line is the proof
			// that the pin and the published key agree.
			if !strings.Contains(out, "signing key verified: "+publishedFingerprint()) {
				t.Errorf("the installer did not report the pinned fingerprint:\n%s", out)
			}

			if v := b.installedVersion(); v != wantVersion {
				t.Errorf("get.whichports.com is serving %q, the newest tag is %q. "+
					"Either a publish did not reach the server or a tag was pushed "+
					"without publishing.", v, wantVersion)
			}
			// Found by name rather than by path: the binary is in /usr/bin
			// from 0.1.12 and was in /usr/local/bin before it, and this
			// stage reads whichever version the server is serving today.
			got := strings.Fields(b.mustSh(`sha256sum "$(command -v whichports-agent)"`))
			t.Logf("published binary sha256 on %s: %v (this checkout builds %s)",
				fam.name, got, f.binarySHA)

			switch fam.name {
			case "ubuntu-26.04":
				source := b.mustRun("cat", "/etc/apt/sources.list.d/whichports.list")
				if !strings.Contains(source, "https://get.whichports.com/deb stable main") {
					t.Errorf("the apt source does not point at the published repository:\n%s", source)
				}
				policy := b.mustRun("apt-cache", "policy", "whichports-agent")
				if !strings.Contains(policy, "get.whichports.com") {
					t.Errorf("apt does not attribute the package to the published repository:\n%s", policy)
				}
			default:
				repo := b.mustRun("cat", "/etc/yum.repos.d/whichports.repo")
				if !strings.Contains(repo, "baseurl=https://get.whichports.com/rpm") {
					t.Errorf("the dnf repository does not point at the published one:\n%s", repo)
				}
				from := strings.TrimSpace(b.mustRun("dnf", "repoquery", "--installed",
					"--qf", "%{from_repo}", "whichports-agent"))
				if from != "whichports" {
					t.Errorf("dnf says the package came from %q, want \"whichports\"", from)
				}
			}

			assertUnitsAfterInstall(t, b)
		})
	}
}

// publishedFingerprint is the fingerprint pinned in the shipped installer,
// pulled out of the constant this package already quotes so the two can never
// drift apart.
func publishedFingerprint() string {
	return strings.Trim(strings.TrimPrefix(publishedFPRLine, "KEY_FPR="), `"`)
}
