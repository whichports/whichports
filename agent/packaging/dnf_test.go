package packaging

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// The installer on dnf, and what it says at the end (docs/RECORD.md 4.460).
//
// dnf reads the metadata of every enabled repository before it installs
// anything. On the test fleet on 2026-09-30 a stalled Rocky 8 mirror held the
// install over ten minutes twice, while the only thing the package needed
// from the distribution, acl, was already installed (docs/RECORD.md 4.220).
// In a plain rockylinux:8 container on 2026-10-14, one enabled repository
// that never answers failed the published installer after 142 seconds, and
// our repository was never asked.
//
// The installer now reads our repository alone when the package's
// dependencies are installed, and every repository otherwise. These tests
// run the installer's own function with a stand-in rpm and dnf.

// dnfInstallFunction returns install.sh's install_with_dnf function, as text.
func dnfInstallFunction(t *testing.T) string {
	t.Helper()
	script := installerSource(t)
	start := strings.Index(script, "install_with_dnf() {")
	if start < 0 {
		t.Fatal("install.sh has no install_with_dnf function, so the installer has " +
			"changed shape and these tests must be updated to match")
	}
	end := strings.Index(script[start:], "\n}\n")
	if end < 0 {
		t.Fatal("install.sh's install_with_dnf function has no end")
	}
	return script[start : start+end+3]
}

// rpmDependencies reads the rpm depends block under overrides in nfpm.yaml,
// the way debDependencies reads the deb one.
func rpmDependencies(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("nfpm.yaml")
	if err != nil {
		t.Fatalf("reading nfpm.yaml: %v", err)
	}
	var deps []string
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case line == "overrides:":
			section = "overrides"
		case section == "overrides" && line == "  rpm:":
			section = "rpm"
		case section == "rpm" && line == "    depends:":
			section = "depends"
		case section == "depends" && strings.HasPrefix(line, "      - "):
			deps = append(deps, strings.TrimSpace(strings.TrimPrefix(line, "      - ")))
		case section == "depends":
			section = "done"
		}
	}
	if len(deps) == 0 {
		t.Fatal("found no rpm depends under overrides in nfpm.yaml, so the file has " +
			"changed shape and this test must be updated to match")
	}
	return deps
}

// dnfRun is one run of install_with_dnf: its exit code, its words, and each
// call of dnf as its list of arguments.
type dnfRun struct {
	code  int
	out   string
	calls [][]string
	env   []string
}

// The options Rocky Linux 8's dnf 4.7.0 lists in its own --help that a stand-in for
// an older dnf accepts. --repo is left out on purpose: a dnf without it must
// still install. Every other option makes it stop with 2, as dnf's own parser
// does on an option it does not know (read on four dnf versions, 2026-10-14).
const olderDnf = `
for a in "$@"; do
  case "$a" in
    -y|install|whichports-agent|--disablerepo=\*|--enablerepo=whichports) ;;
    *) echo "dnf: error: unrecognized arguments: $a" >&2; exit 2 ;;
  esac
done
`

// runDnfInstall runs install.sh's own install_with_dnf with ENROLL set as
// given, on a machine where rpm knows the capabilities in `installed`, and
// with a dnf whose body is `dnf` after it has written down how it was called
// and with what WHICHPORTS_INSTALLER_CONNECTS.
func runDnfInstall(t *testing.T, enroll string, installed []string, dnf string) dnfRun {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell scripts are not exercised on Windows")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "dnf.calls")
	env := filepath.Join(dir, "dnf.env")
	// rpm -q --whatprovides ends with the number of capabilities nothing
	// provides, as the real one did on four systems on 2026-10-14.
	rpm := "#!/bin/sh\nmissing=0\nfor a in \"$@\"; do\n  case \"$a\" in -q|--whatprovides) continue ;; esac\n" +
		"  case \" " + strings.Join(installed, " ") + " \" in *\" $a \"*) echo \"$a-1.0-1.x86_64\" ;; " +
		"*) echo \"no package provides $a\"; missing=$((missing + 1)) ;; esac\ndone\nexit $missing\n"
	stub := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\t' \"$a\"; done >> " + shellQuote(calls) + "\n" +
		"printf '\\n' >> " + shellQuote(calls) + "\n" +
		"printf '%s\\n' \"${WHICHPORTS_INSTALLER_CONNECTS-unset}\" >> " + shellQuote(env) + "\n" +
		dnf + "\nexit 0\n"
	for name, body := range map[string]string{"rpm": rpm, "dnf": stub} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("this machine has no sh: %v", err)
	}
	cmd := exec.Command(shell, "-c", "set -eu\nENROLL="+enroll+"\n"+dnfInstallFunction(t)+"\ninstall_with_dnf")
	cmd.Env = []string{"PATH=" + bin}
	out, runErr := cmd.CombinedOutput()
	run := dnfRun{out: string(out)}
	var exit *exec.ExitError
	if errors.As(runErr, &exit) {
		run.code = exit.ExitCode()
	} else if runErr != nil {
		t.Fatal(runErr)
	}
	if data, err := os.ReadFile(calls); err == nil {
		for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			run.calls = append(run.calls, strings.Split(strings.TrimSuffix(line, "\t"), "\t"))
		}
	}
	if data, err := os.ReadFile(env); err == nil {
		run.env = strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	}
	return run
}

var (
	ourRepositoryAlone = []string{"install", "-y", "--disablerepo=*", "--enablerepo=whichports", "whichports-agent"}
	everyRepository    = []string{"install", "-y", "whichports-agent"}
)

func oneCall(t *testing.T, run dnfRun, want []string) {
	t.Helper()
	if len(run.calls) != 1 {
		t.Fatalf("want dnf called once, got %d calls %q:\n%s", len(run.calls), run.calls, run.out)
	}
	if strings.Join(run.calls[0], " ") != strings.Join(want, " ") {
		t.Errorf("dnf was called with %q, want %q", run.calls[0], want)
	}
}

// ------------------------------------------------------------ edge cases

// Another repository never answers. With the dependencies installed, dnf is
// told to read ours alone, so the one that never answers is never asked.
func TestARepositoryThatNeverAnswersIsNotReadWhenTheDependenciesAreInstalled(t *testing.T) {
	never := `case " $* " in *" --disablerepo=* "*) ;; *)
  echo "Error: Failed to download metadata for repo 'never-answers'" >&2; exit 1 ;; esac`
	run := runDnfInstall(t, "no", rpmDependencies(t), never)
	if run.code != 0 {
		t.Fatalf("the install failed on a repository it does not need:\n%s", run.out)
	}
	oneCall(t, run, ourRepositoryAlone)
}

// Ours cannot be reached. dnf's own words end the install, with dnf's code,
// and the installer does not try again over every repository: that would
// wait on all of them to fail in the same way.
func TestOurRepositoryUnreachableEndsTheInstallWithDnfsOwnWords(t *testing.T) {
	ours := `echo "Error: Failed to download metadata for repo 'whichports': Cannot download repomd.xml" >&2; exit 1`
	run := runDnfInstall(t, "no", rpmDependencies(t), ours)
	if run.code != 1 {
		t.Fatalf("want the install to end with dnf's 1, got %d:\n%s", run.code, run.out)
	}
	if !strings.Contains(run.out, "Failed to download metadata for repo 'whichports'") {
		t.Errorf("dnf's own words are not shown:\n%s", run.out)
	}
	oneCall(t, run, ourRepositoryAlone)
}

// The package is already installed. dnf is asked the same way, and what
// dnf does with an installed package is dnf's, as it was before.
func TestThePackageAlreadyInstalledIsAskedTheSameWay(t *testing.T) {
	already := `echo "Package whichports-agent-0.1.12-1.x86_64 is already installed."; echo "Nothing to do."`
	run := runDnfInstall(t, "no", rpmDependencies(t), already)
	if run.code != 0 {
		t.Fatalf("an installed package failed the install:\n%s", run.out)
	}
	oneCall(t, run, ourRepositoryAlone)
	if !strings.Contains(run.out, "is already installed") {
		t.Errorf("dnf's own words are not shown:\n%s", run.out)
	}
}

// A dnf older than --repo. The installer uses the pair dnf's manual calls
// --repo a shortcut for, which Rocky Linux 8's dnf 4.7.0 lists in its own --help.
func TestAnOlderDnfWithoutTheRepoOptionStillInstalls(t *testing.T) {
	run := runDnfInstall(t, "no", rpmDependencies(t), olderDnf)
	if run.code != 0 {
		t.Fatalf("an older dnf refused the installer's options:\n%s", run.out)
	}
	oneCall(t, run, ourRepositoryAlone)
	// and on the path that reads every repository too
	run = runDnfInstall(t, "no", nil, olderDnf)
	if run.code != 0 {
		t.Fatalf("an older dnf refused the installer's options:\n%s", run.out)
	}
}

// A dependency is missing. It comes from the distribution's repositories,
// so dnf reads them all, as before, and the line before says why.
func TestEachMissingDependencyMakesDnfReadEveryRepository(t *testing.T) {
	deps := rpmDependencies(t)
	for i, missing := range deps {
		installed := append(append([]string{}, deps[:i]...), deps[i+1:]...)
		run := runDnfInstall(t, "no", installed, "")
		if run.code != 0 {
			t.Fatalf("without %s the install failed:\n%s", missing, run.out)
		}
		oneCall(t, run, everyRepository)
		if !strings.Contains(run.out, "reading every repository") {
			t.Errorf("without %s nothing says every repository is read:\n%s", missing, run.out)
		}
	}
}

// --------------------------------------------------------- the usual case

func TestTheDependenciesTheInstallerChecksAreThePackagesOwn(t *testing.T) {
	fn := dnfInstallFunction(t)
	line := ""
	for _, l := range strings.Split(fn, "\n") {
		if strings.Contains(l, "rpm -q --whatprovides") {
			line = l
		}
	}
	if line == "" {
		t.Fatal("install_with_dnf does not ask rpm which dependencies are installed")
	}
	fields := strings.Fields(line[strings.Index(line, "--whatprovides")+len("--whatprovides"):])
	var checked []string
	for _, f := range fields {
		if strings.HasPrefix(f, ">") || f == "2>&1;" || f == "then" || strings.HasPrefix(f, "2>") {
			break
		}
		checked = append(checked, f)
	}
	want := append([]string{}, rpmDependencies(t)...)
	sort.Strings(checked)
	sort.Strings(want)
	if strings.Join(checked, " ") != strings.Join(want, " ") {
		t.Errorf("install_with_dnf checks %q, the package depends on %q", checked, want)
	}
}

func TestWithTheDependenciesInstalledDnfReadsOursAlone(t *testing.T) {
	run := runDnfInstall(t, "no", rpmDependencies(t), "")
	if run.code != 0 {
		t.Fatalf("install_with_dnf failed:\n%s", run.out)
	}
	oneCall(t, run, ourRepositoryAlone)
}

// The options choose which repositories are read, never how a package is
// verified: the repository file keeps both checks and the local key, and no
// dnf call in the installer turns a check off.
func TestTheInstallerNeverSwitchesASignatureCheckOff(t *testing.T) {
	script := installerSource(t)
	for _, want := range []string{"gpgcheck=1\n", "repo_gpgcheck=1\n", "gpgkey=file://$KEYRING_RPM\n"} {
		if !strings.Contains(script, want) {
			t.Errorf("the repository file no longer says %q", want)
		}
	}
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, off := range []string{"nogpgcheck", "no-gpgchecks", "gpgcheck=0", "gpgcheck=False",
			"--setopt", "skip_if_unavailable", "localpkg_gpgcheck"} {
			if strings.Contains(trimmed, off) {
				t.Errorf("install.sh says %q: %s", off, trimmed)
			}
		}
	}
}

// SI-4 holds in the shell: nothing in the installer builds a string and
// hands it to a shell to run.
func TestTheInstallerRunsNoBuiltString(t *testing.T) {
	for _, line := range strings.Split(installerSource(t), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "echo ") {
			continue
		}
		for _, bad := range []string{"eval ", "sh -c", "bash -c", "$(echo"} {
			if strings.Contains(trimmed, bad) {
				t.Errorf("install.sh runs a built string with %q: %s", bad, trimmed)
			}
		}
	}
}
