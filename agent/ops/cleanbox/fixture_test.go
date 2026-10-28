// Package cleanbox tests the public install path on a box with nothing on it.
//
// The install path is one line the page tells a stranger to run as root:
//
//	curl -fsSL https://get.whichports.com | sh
//
// Until this file existed nothing tested it. It had been run by hand on hosts
// that already had things on them, and once on an old server of ours, which
// docs/RECORD.md 4.48 calls the nearest thing to a clean-box test the product
// has had. That is an anecdote, not a test, and 4.48 is also where the cost of
// having no test showed up: a pre-remove scriptlet disabled the timer on every
// upgrade and silenced all three production hosts, and the same host had been
// running a hand-built binary with no whichports apt source configured at all,
// so no amount of publishing could ever have upgraded it.
//
// The clean box is a container. Two families matter because the agent ships
// both a .deb and an .rpm, so every assertion runs on Ubuntu and on AlmaLinux.
//
// # What is tested offline and what needs the network
//
// Everything here except TestPublishedInstaller runs against a repository built
// on this machine from agent/packaging/, signed with a throwaway key generated
// for the run, and served over file:// out of a directory mounted into the
// container. No get.whichports.com, no CDN, no DNS. That is deliberate: a test
// that fails when a CDN hiccups is a test people learn to ignore.
//
// What that costs is honest to state. The offline run proves the installer's
// repository configuration, the package manager's signature checks, the
// scriptlets, the unit and timer states, the upgrade path and the removal path.
// It does not prove that get.whichports.com serves the right bytes over https,
// and it does not prove the fingerprint pinned in install.sh is the key that
// signs the published packages. TestPublishedInstaller covers those two and
// only those two, and it is opt-in because it needs the network.
//
// # Running it
//
//	cd agent && WHICHPORTS_CLEANBOX=1 go test -v ./ops/cleanbox/
//	cd agent && WHICHPORTS_CLEANBOX_ONLINE=1 go test -v -run Published ./ops/cleanbox/
//
// Both gates are off by default because a run takes minutes and needs docker,
// and a slow suite is one people stop running. The offline half runs on every
// pull request that touches agent/ (.github/workflows/agent.yml), so it does
// not depend on anyone remembering.
//
// # On an arm64 machine
//
// The boxes are amd64, so on an arm64 machine they run under the container
// runtime's emulator. Measured on 2026-10-06 with Docker Desktop 4.94 and
// Rosetta (docs/RECORD.md 4.406): no systemd service starts there. A unit
// whose only command is /bin/true ends with status 255 in these images. So
// the three tests that start the agent's service fail on such a machine, and
// the stages after the first start are not reached. Read such a failure as
// the emulator until it shows on amd64.
//
// Do not make the boxes arm64 to get round that on a machine anybody shares.
// It works, and every test passes natively. But the boxes are privileged and
// run systemd, and Ubuntu's systemd-binfmt service then writes the list of
// binary formats of the one kernel all containers share: it registers its own
// entry and, when the box stops, unregisters every other one, the emulator's
// among them. From then on no amd64 container starts on that machine, each
// says "exec format error", until the container runtime is restarted. A
// native run needs systemd-binfmt.service masked in the image first.
package cleanbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The two fixture versions. They are deliberately absurd so a fixture package
// can never be mistaken for a published one, and ordered so the second is an
// upgrade of the first.
const (
	oldVersion = "9.9.8"
	newVersion = "9.9.9"
)

// The throwaway signing identity. Nothing outside this test ever sees it, and
// .invalid is reserved by RFC 2606 so the address cannot resolve or be mailed.
const (
	testKeyUID   = "whichports clean-box test <cleanbox@test.invalid>"
	testKeyEmail = "cleanbox@test.invalid"
)

// A second throwaway key, used only to sign a repository the box has no reason
// to trust. It stands for whoever took over the mirror.
const (
	impostorUID   = "whichports clean-box impostor <impostor@test.invalid>"
	impostorEmail = "impostor@test.invalid"
)

// The two lines the test rewrites in install.sh, quoted exactly as they appear
// in the shipped script. Everything else in the script runs verbatim.
//
// Both are asserted to exist exactly once before anything is replaced. That
// assertion is the point: on 2026-08-16 this repository produced green results
// three times over from checks whose target string was not there at all, so a
// rewrite that silently matches nothing is a known way to get a test that tests
// nothing. If install.sh changes shape, this fails loudly instead.
const (
	publishedBaseLine = `BASE="https://get.whichports.com"`
	publishedFPRLine  = `KEY_FPR="3EEDC9C6E4940A815D42CE43680A90826E2C982D"`
)

// Container image tags built by this test.
const (
	ubuntuImage = "whichports-cleanbox-ubuntu"
	almaImage   = "whichports-cleanbox-almalinux"
)

// family is one of the two package families, with the commands that differ.
type family struct {
	name       string // subtest name
	image      string // the prepared image with systemd, curl and gpg
	baseImage  string // the untouched distribution image, for the no-gpg case
	dockerfile string
}

var families = []family{
	{
		name:       "ubuntu-26.04",
		image:      ubuntuImage,
		baseImage:  "ubuntu:26.04",
		dockerfile: "images/ubuntu.Dockerfile",
	},
	{
		name:       "almalinux-10",
		image:      almaImage,
		baseImage:  "almalinux:10",
		dockerfile: "images/almalinux.Dockerfile",
	},
}

// fixture is everything built once per run: a signing key, two package
// versions, three repository trees, and the installer rewritten to point at
// them.
type fixture struct {
	root     string // short-lived directory holding all of it
	agentDir string // the agent/ directory of this checkout

	keyFile string // armored private key, for nfpm and the repo builder
	keyFPR  string // its fingerprint, which replaces the pinned one

	repoOld      string // 9.9.8 only
	repoBoth     string // 9.9.8 and 9.9.9, so the old install can upgrade
	repoUnsigned string // 9.9.9 rpm built with no signature, metadata still signed

	installer string // install.sh with BASE and KEY_FPR rewritten
	// One sha per version, because each version is built with its own
	// PKG_VERSION compiled in, so the two binaries differ.
	binarySHA    string // sha256 of the binary inside the 9.9.8 packages
	newBinarySHA string // sha256 of the binary inside the 9.9.9 packages
	buildStart   time.Time
}

var fix *fixture

func TestMain(m *testing.M) {
	if os.Getenv("WHICHPORTS_CLEANBOX") == "" {
		// Nothing is built and every test skips with a reason. The skip is
		// visible in -v output and the CI job sets the variable, so this is a
		// speed gate and not a way for the check to quietly disappear.
		os.Exit(m.Run())
	}
	var err error
	fix, err = buildFixture()
	if err != nil {
		fmt.Fprintf(os.Stderr, "clean-box fixture: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	if os.Getenv("WHICHPORTS_CLEANBOX_KEEP") == "" {
		os.RemoveAll(fix.root)
	} else {
		fmt.Fprintf(os.Stderr, "clean-box fixture kept at %s\n", fix.root)
	}
	os.Exit(code)
}

// requireFixture skips a test that needs the offline fixture when the gate is
// off, naming the command that turns it on.
func requireFixture(t *testing.T) *fixture {
	t.Helper()
	if fix == nil {
		t.Skip("clean-box install test is off. Run: WHICHPORTS_CLEANBOX=1 go test ./ops/cleanbox/")
	}
	return fix
}

func buildFixture() (*fixture, error) {
	agentDir, err := filepath.Abs("../..")
	if err != nil {
		return nil, err
	}
	// Prove we are pointed at the agent tree before building anything from it.
	for _, must := range []string{"packaging/install.sh", "packaging/nfpm.yaml", "Makefile"} {
		if _, err := os.Stat(filepath.Join(agentDir, must)); err != nil {
			return nil, fmt.Errorf("expected %s under %s: %w", must, agentDir, err)
		}
	}
	for _, tool := range []string{"docker", "gpg", "make", "nfpm", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			return nil, fmt.Errorf("%s is required and was not found on PATH", tool)
		}
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("docker daemon is not answering: %v\n%s", err, out)
	}

	// /tmp rather than the usual temporary directory, for two reasons that are
	// both about path length and both bite on a Mac: gpg-agent's unix socket
	// lives inside GNUPGHOME and blows past the 104 byte sockaddr limit under a
	// long path, and docker's default set of shareable host directories is
	// short and predictable.
	root, err := os.MkdirTemp("/tmp", "whichports-cleanbox-")
	if err != nil {
		return nil, err
	}
	// MkdirTemp gives 0700, and the served repository underneath this has to be
	// readable by unprivileged users inside the container (see makeWorldReadable).
	// The throwaway private key inside stays 0600 and is not affected.
	if err := os.Chmod(root, 0o755); err != nil {
		return nil, err
	}
	f := &fixture{root: root, agentDir: agentDir, buildStart: time.Now()}

	if err := f.generateKey(); err != nil {
		return nil, err
	}
	if err := f.buildPackages(); err != nil {
		return nil, err
	}
	if err := f.buildRepos(); err != nil {
		return nil, err
	}
	if err := f.rewriteInstaller(); err != nil {
		return nil, err
	}
	if err := f.buildImages(); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "clean-box fixture ready in %s\n",
		time.Since(f.buildStart).Round(time.Second))
	return f, nil
}

// generateKey makes a throwaway RSA 4096 signing key, the same algorithm and
// size as the real whichports key, so rpm and apt are asked to verify the same
// kind of signature they verify in production.
func (f *fixture) generateKey() error {
	home := filepath.Join(f.root, "gnupg")
	if err := os.Mkdir(home, 0o700); err != nil {
		return err
	}
	gpg := func(args ...string) (string, error) {
		cmd := exec.Command("gpg", append([]string{"--homedir", home, "--batch",
			"--pinentry-mode", "loopback", "--passphrase", ""}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("gpg %v: %v\n%s", args, err, out)
		}
		return string(out), nil
	}
	for _, uid := range []string{testKeyUID, impostorUID} {
		if _, err := gpg("--quick-generate-key", uid, "rsa4096", "sign", "never"); err != nil {
			return err
		}
	}
	// Selected by address rather than by position, so adding a key later cannot
	// quietly change which fingerprint the whole run is built around.
	listing, err := gpg("--with-colons", "--list-keys", testKeyEmail)
	if err != nil {
		return err
	}
	f.keyFPR = firstFingerprint(listing)
	if len(f.keyFPR) != 40 {
		return fmt.Errorf("could not read the test key fingerprint from:\n%s", listing)
	}
	// Only the publishing key's secret half leaves the keyring, because that is
	// the only one nfpm and the repository builder are given.
	secret, err := gpg("--armor", "--export-secret-keys", testKeyEmail)
	if err != nil {
		return err
	}
	f.keyFile = filepath.Join(f.root, "test-signing-key.asc")
	return os.WriteFile(f.keyFile, []byte(secret), 0o600)
}

// firstFingerprint pulls the first fpr line out of gpg --with-colons output.
func firstFingerprint(colons string) string {
	for _, line := range strings.Split(colons, "\n") {
		if strings.HasPrefix(line, "fpr:") {
			fields := strings.Split(line, ":")
			if len(fields) > 9 {
				return fields[9]
			}
		}
	}
	return ""
}

// buildPackages builds the static binary the way the Makefile builds it for a
// release, then the same nfpm spec the release uses, at two versions signed
// with the throwaway key and one deliberately unsigned.
//
// The binary goes to agent/dist/, which is where `make agent` always puts it and
// which git ignores. The packages do not: they go to the fixture directory, so a
// run of this test cannot disturb a set of release packages sitting in dist/.
func (f *fixture) buildPackages() error {
	// One binary per version, each built with its own PKG_VERSION, because the
	// Makefile compiles that value into the binary and `--version` reports it.
	// Packaging one binary as both versions would ship a 9.9.9 package holding
	// a binary that calls itself 9.9.8, which is the exact mismatch stage 3 and
	// the upgrade stage now assert cannot happen.
	binary := filepath.Join(f.agentDir, "dist", "whichports-agent")

	signedOld := filepath.Join(f.root, "pkgs-old")
	signedNew := filepath.Join(f.root, "pkgs-new")
	both := filepath.Join(f.root, "pkgs-both")
	unsigned := filepath.Join(f.root, "pkgs-unsigned")
	for _, d := range []string{signedOld, signedNew, both, unsigned} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	// Each version is built and then packaged before the next build overwrites
	// dist/, because nfpm reads the binary from there. The order is the point:
	// packaging one binary as both versions would ship a 9.9.9 package holding
	// a binary that calls itself 9.9.8, and that mismatch is what stage 3 and
	// the upgrade stage now assert cannot happen.
	built := map[string]string{}
	for _, v := range []struct {
		version string
		signed  string
	}{{oldVersion, signedOld}, {newVersion, signedNew}} {
		if out, err := f.make("agent", "PKG_VERSION="+v.version); err != nil {
			return fmt.Errorf("make agent PKG_VERSION=%s: %v\n%s", v.version, err, out)
		}
		sum, err := sha256File(binary)
		if err != nil {
			return fmt.Errorf("hashing the built binary: %w", err)
		}
		built[v.version] = sum
		for _, packager := range []string{"deb", "rpm"} {
			if err := f.nfpm(packager, v.version, v.signed, true); err != nil {
				return err
			}
		}
		// The unsigned tree is the "somebody built this themselves" case, and it
		// is the new version, so it is packaged from this same binary while it
		// is still the one in dist/.
		if v.version == newVersion {
			if err := f.nfpm("rpm", v.version, unsigned, false); err != nil {
				return err
			}
		}
	}
	// If PKG_VERSION never reached the compiler the two binaries are identical,
	// and every version assertion downstream would pass by accident. Fail here
	// instead, where the reason is visible.
	if built[oldVersion] == built[newVersion] {
		return fmt.Errorf("the two builds produced the same binary, so PKG_VERSION "+
			"did not reach the compiler and the version assertions would prove "+
			"nothing (both %s)", built[oldVersion])
	}
	f.binarySHA = built[oldVersion]
	f.newBinarySHA = built[newVersion]

	// The unsigned tree needs a .deb only because the repository builder copies
	// both families in one pass, so the signed old .deb is reused there.
	if err := copyGlob(filepath.Join(signedOld, "*.deb"), unsigned); err != nil {
		return err
	}
	for _, src := range []string{signedOld, signedNew} {
		if err := copyGlob(filepath.Join(src, "*"), both); err != nil {
			return err
		}
	}
	return nil
}

// nfpm runs the release packaging spec at one version into one directory.
// Signing is on when signed is true, which is exactly how the release build
// turns it on: by having SIGNING_KEY_FILE in the environment.
func (f *fixture) nfpm(packager, version, target string, signed bool) error {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"PKG_VERSION=" + version}
	if signed {
		env = append(env, "SIGNING_KEY_FILE="+f.keyFile, "NFPM_PASSPHRASE=")
	}
	cmd := exec.Command("nfpm", "package",
		"--config", "packaging/nfpm.yaml", "--packager", packager, "--target", target)
	cmd.Dir = f.agentDir
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nfpm %s %s: %v\n%s", packager, version, err, out)
	}
	return nil
}

// buildRepos builds three real signed repository trees with the same target the
// release publish uses, so the metadata, the layout and the signatures are the
// ones an operator's package manager actually meets.
func (f *fixture) buildRepos() error {
	f.repoOld = filepath.Join(f.root, "repo-old")
	f.repoBoth = filepath.Join(f.root, "repo-both")
	f.repoUnsigned = filepath.Join(f.root, "repo-unsigned")
	for _, pair := range [][2]string{
		{filepath.Join(f.root, "pkgs-old"), f.repoOld},
		{filepath.Join(f.root, "pkgs-both"), f.repoBoth},
		{filepath.Join(f.root, "pkgs-unsigned"), f.repoUnsigned},
	} {
		out, err := f.make("repo",
			"REPO_PKG_DIR="+pair[0],
			"REPO_OUT="+pair[1],
			"REPO_KEY_ID="+testKeyEmail)
		if err != nil {
			return fmt.Errorf("make repo from %s: %v\n%s", pair[0], err, out)
		}
	}
	return nil
}

// make runs one target in agent/ with the signing environment the release
// publish sets. The passphrase is empty because the throwaway key has none.
func (f *fixture) make(target string, vars ...string) (string, error) {
	cmd := exec.Command("make", append([]string{target}, vars...)...)
	cmd.Dir = f.agentDir
	cmd.Env = append(os.Environ(),
		"SIGNING_KEY_FILE="+f.keyFile,
		"NFPM_PASSPHRASE=",
		"REPO_GPG_PASSPHRASE=")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// rewriteInstaller produces the copy of install.sh the offline tests run: the
// shipped script with the base URL pointed at the mounted repository and the
// pinned fingerprint pointed at the throwaway key. Nothing else is touched.
//
// Both target lines must be present exactly once or this fails, because a
// substitution that matches nothing would leave the script pointed at the real
// site and quietly turn every offline assertion into a network test.
func (f *fixture) rewriteInstaller() error {
	raw, err := os.ReadFile(filepath.Join(f.agentDir, "packaging", "install.sh"))
	if err != nil {
		return err
	}
	script := string(raw)
	for _, line := range []string{publishedBaseLine, publishedFPRLine} {
		if n := strings.Count(script, line); n != 1 {
			return fmt.Errorf("packaging/install.sh contains %q %d times, want exactly 1. "+
				"The installer changed shape and this test must be updated to match", line, n)
		}
	}
	rewritten := strings.Replace(script, publishedBaseLine, `BASE="file:///repo"`, 1)
	rewritten = strings.Replace(rewritten, publishedFPRLine, `KEY_FPR="`+f.keyFPR+`"`, 1)
	if rewritten == script {
		return fmt.Errorf("rewriting install.sh changed nothing")
	}
	// No live reference to the published site may survive. Comments still name
	// it, and should, so comments are skipped: the script's own `#` lines, and
	// the `//` lines of the apt configuration the installer writes through the
	// APTCONF heredoc, which tell an operator reading that file where upgrades
	// come from. `//` is skipped only inside that heredoc, because outside it a
	// line starting with `//` is a path the shell would run. Until 2026-09-29
	// only `#` was skipped, so this refused every run from 03c46b0 on.
	inAptConf := false
	for n, line := range strings.Split(rewritten, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "APTCONF" {
			inAptConf = false
			continue
		}
		if strings.HasPrefix(trimmed, "#") || (inAptConf && strings.HasPrefix(trimmed, "//")) {
			continue
		}
		if strings.Contains(line, "get.whichports.com") {
			return fmt.Errorf("line %d of the rewritten installer still points at the "+
				"published site, so the offline test would silently become a network "+
				"test: %s", n+1, line)
		}
		if strings.Contains(line, "<<APTCONF") {
			inAptConf = true
		}
	}
	f.installer = filepath.Join(f.root, "install.sh")
	return os.WriteFile(f.installer, []byte(rewritten), 0o644)
}

// buildImages builds the two clean-box images.
func (f *fixture) buildImages() error {
	for _, fam := range families {
		cmd := exec.Command("docker", "build", "--platform=linux/amd64",
			"-q", "-t", fam.image, "-f", fam.dockerfile, ".")
		cmd.Dir = mustCWD()
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("docker build %s: %v\n%s", fam.image, err, out)
		}
	}
	return nil
}

func mustCWD() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return wd
}

// serve lays one repository tree plus the rewritten installer into a fresh
// directory that becomes the container's /repo. Tests get their own copy so
// one test swapping in a newer repository cannot disturb another.
func (f *fixture) serve(t *testing.T, repo string) string {
	t.Helper()
	dir, err := os.MkdirTemp(f.root, "served-")
	if err != nil {
		t.Fatalf("creating a served directory: %v", err)
	}
	f.swap(t, dir, repo)
	return dir
}

// swap replaces what a served directory holds, which is how a test moves a box
// from "the repository has one version" to "the repository has a newer one".
func (f *fixture) swap(t *testing.T, served, repo string) {
	t.Helper()
	if out, err := exec.Command("sh", "-c",
		"cp -R "+shellQuote(repo)+"/. "+shellQuote(served)+"/").CombinedOutput(); err != nil {
		t.Fatalf("copying %s into %s: %v\n%s", repo, served, err, out)
	}
	// The repository builder writes its own copy of the shipped installer into
	// the tree. Overwrite it with the rewritten one, and prove the file landed,
	// because a served tree carrying the published installer would point the
	// box at the real site.
	if err := copyFile(f.installer, filepath.Join(served, "install.sh")); err != nil {
		t.Fatalf("placing the rewritten installer: %v", err)
	}
	placed, err := os.ReadFile(filepath.Join(served, "install.sh"))
	if err != nil {
		t.Fatalf("reading back the served installer: %v", err)
	}
	if !strings.Contains(string(placed), `BASE="file:///repo"`) {
		t.Fatalf("the served installer is not the rewritten one")
	}
	if err := makeWorldReadable(served); err != nil {
		t.Fatalf("making the served repository readable: %v", err)
	}
}

// makeWorldReadable sets the served tree to the modes a published repository
// actually has, 0755 on directories and 0644 on files.
//
// It is here because of a real failure rather than for tidiness. Go's MkdirTemp
// makes 0700 directories, and on a Linux host a bind mount carries those modes
// straight into the container, where two things then cannot read the
// repository: apt, which drops to the unprivileged _apt user for every fetch,
// and the unprivileged user the non-root refusal test uses. Both broke in CI
// while passing on a Mac, because Docker Desktop's file sharing flattens
// ownership and permissions and hides the difference. A repository nobody but
// root can read is not a repository anyone would publish, so this makes the
// fixture more faithful rather than more permissive.
func makeWorldReadable(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(path, 0o755)
		}
		return os.Chmod(path, 0o644)
	})
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func copyGlob(pattern, dstDir string) error {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	if len(matches) == 0 {
		return fmt.Errorf("no files matched %s", pattern)
	}
	for _, m := range matches {
		if err := copyFile(m, filepath.Join(dstDir, filepath.Base(m))); err != nil {
			return err
		}
	}
	return nil
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// signWithImpostor re-signs a served repository's metadata with a key the box
// has never heard of, leaving perfectly valid armor behind. That is the
// unambiguous version of "somebody swapped the repository": a real signature,
// made by the wrong hand.
//
// The first version of this helper flipped a byte inside the armor instead, and
// it produced a false result worth writing down. A flipped byte breaks the
// armor's CRC, and dnf 5 on AlmaLinux 10.2 installed the package anyway, while
// refusing the very same repository when the signature file was missing and
// when it was signed by an unknown key. So a byte flip tested something other
// than the signature check, and a negative test that passes for the wrong
// reason is the failure mode this repository keeps finding. Signing with
// another key removes the ambiguity: there is nothing wrong with the file
// except who made it.
func (f *fixture) signWithImpostor(t *testing.T, served string, fam family) {
	t.Helper()
	switch fam.name {
	case "ubuntu-26.04":
		release := filepath.Join(served, "deb/dists/stable/Release")
		mustExistOnDisk(t, release, "apt-ftparchive writes it")
		f.gpgSign(t, "--clearsign", release, filepath.Join(served, "deb/dists/stable/InRelease"))
		f.gpgSign(t, "--detach-sign", release, filepath.Join(served, "deb/dists/stable/Release.gpg"))
	default:
		repomd := filepath.Join(served, "rpm/repodata/repomd.xml")
		mustExistOnDisk(t, repomd, "createrepo_c writes it")
		f.gpgSign(t, "--detach-sign", repomd, filepath.Join(served, "rpm/repodata/repomd.xml.asc"))
	}
}

// gpgSign writes one armored signature made by the impostor key, and proves the
// file it wrote is a signature rather than an empty file left by a failed run.
func (f *fixture) gpgSign(t *testing.T, mode, in, out string) {
	t.Helper()
	cmd := exec.Command("gpg", "--homedir", filepath.Join(f.root, "gnupg"),
		"--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "",
		"--local-user", impostorEmail, mode, "--armor", "-o", out, in)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("signing %s with the impostor key: %v\n%s", in, err, combined)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading back %s: %v", out, err)
	}
	if !strings.Contains(string(data), "-----BEGIN PGP SIGNATURE-----") &&
		!strings.Contains(string(data), "-----BEGIN PGP SIGNED MESSAGE-----") {
		t.Fatalf("%s is not an armored signature, so the test would prove nothing:\n%s",
			out, first200(string(data)))
	}
	// Written after the tree was made readable, so it needs the same treatment
	// or the package manager fails to fetch it instead of failing to verify it,
	// which would be a refusal for the wrong reason.
	if err := os.Chmod(out, 0o644); err != nil {
		t.Fatalf("making %s readable: %v", out, err)
	}
}

// removeSignatures takes the repository's signatures away entirely, which is
// the other half of the question: a package manager has to refuse an unsigned
// repository as firmly as a wrongly signed one.
func removeSignatures(t *testing.T, served string, fam family) {
	t.Helper()
	var paths []string
	switch fam.name {
	case "ubuntu-26.04":
		paths = []string{"deb/dists/stable/InRelease", "deb/dists/stable/Release.gpg"}
	default:
		paths = []string{"rpm/repodata/repomd.xml.asc"}
	}
	for _, rel := range paths {
		full := filepath.Join(served, rel)
		mustExistOnDisk(t, full, "the repository builder signs the metadata")
		if err := os.Remove(full); err != nil {
			t.Fatalf("removing %s: %v", rel, err)
		}
	}
}

func mustExistOnDisk(t *testing.T, path, why string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist because %s: %v", path, why, err)
	}
}

func first200(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
