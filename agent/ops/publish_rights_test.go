package ops

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The tree publish.sh sends to get.whichports.com has to be readable by the
// web server there, whatever the umask of the terminal the publish ran in.
//
// On 13 October it was not. The terminal's umask was 077, `make repo` made
// dist-repo with mkdir, which takes the umask, so the folder was 700, and
// `rsync -a` copied that mode onto /srv/get.whichports.com. Caddy may not
// enter a folder it cannot read and answers 403 then, so every path did:
// the install script, the key and both repositories (docs/RECORD.md 4.456,
// 4.460).

// lineOf returns the one line of a file that contains `needle`.
func lineOf(t *testing.T, path, needle string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var found []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, needle) {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s has %d lines with %q, want exactly one: %q", path, len(found), needle, found)
	}
	return found[0]
}

// publishLinesBetweenBuildAndSend returns publish.sh's own lines after the
// one that runs `make repo` and before the rsync that sends the tree.
func publishLinesBetweenBuildAndSend(t *testing.T) string {
	t.Helper()
	lines := strings.Split(publishSource(t), "\n")
	start, end := -1, -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "make repo") && !strings.HasPrefix(trimmed, "#") {
			start = i
		}
		if strings.HasPrefix(trimmed, "rsync ") {
			end = i
		}
	}
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("publish.sh: make repo at line %d and rsync at line %d, want the build before the send", start+1, end+1)
	}
	return strings.Join(lines[start+1:end], "\n")
}

func runIn(t *testing.T, dir, script string) {
	t.Helper()
	runInWithPath(t, dir, "/bin:/usr/bin", script)
}

func runInWithPath(t *testing.T, dir, path, script string) {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + path}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("running %q failed: %v\n%s", script, err, out)
	}
}

// standInPython returns a folder holding a python3 that stands in for
// selfhost/release_installer.py: it writes what it was asked, so a test reads
// back the publish's own call. The stamping itself is release_installer.py's,
// and selfhost/test_release_installer.py tests it.
func standInPython(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	fake := "#!/bin/sh\necho \"stamped: $*\"\n"
	if err := os.WriteFile(filepath.Join(bin, "python3"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// betweenBuildAndSend is publish.sh's own lines after the build and before
// the send, with the names they read set to something harmless.
func betweenBuildAndSend(t *testing.T) string {
	t.Helper()
	return "set -eu\numask 077\nDEST=nowhere\nPUBLIC=/the/public/clone\nTAG=v9.9.9\n" +
		publishLinesBetweenBuildAndSend(t)
}

func modeOf(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

// buildUnderUmask077 makes dist-repo in dir the way `make repo` does, with
// the Makefile's own line, under umask 077, and fills it the way the
// repository container does: folders 755 and files 644 and 755. One folder
// and one file are made under the umask too, since what the tree holds can
// come from anywhere.
func buildUnderUmask077(t *testing.T, dir string) {
	t.Helper()
	line := strings.TrimSpace(lineOf(t, "../Makefile", "mkdir -p $(REPO_OUT)"))
	line = strings.ReplaceAll(line, "$(REPO_OUT)", "dist-repo")
	runIn(t, dir, "umask 077; "+line)
	if got := modeOf(t, filepath.Join(dir, "dist-repo")); got != 0o700 {
		t.Fatalf("under umask 077 the Makefile's line made dist-repo %o, the test rests on 700", got)
	}
	files := map[string]fs.FileMode{
		"install.sh":                      0o755,
		"whichports-signing-public.asc":   0o644,
		"deb/dists/stable/InRelease":      0o644,
		"deb/pool/main/w/whichports.deb":  0o644,
		"rpm/repodata/repomd.xml":         0o644,
		"rpm/repodata/repomd.xml.asc":     0o644,
		"made-under-the-umask/a-file.txt": 0o600,
	}
	for name, mode := range files {
		path := filepath.Join(dir, "dist-repo", name)
		folder := 0o755
		if strings.HasPrefix(name, "made-under-the-umask/") {
			folder = 0o700
		}
		if err := os.MkdirAll(filepath.Dir(path), fs.FileMode(folder)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(dir, "dist-repo", "made-under-the-umask"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestTheTreeSentIsReadableToTheSiteWhateverTheUmask(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("publish.sh is a POSIX shell script")
	}
	dir := t.TempDir()
	buildUnderUmask077(t, dir)
	// publish.sh's own lines between the build and the send, under the same
	// umask, with the names they read set to something harmless. The
	// installer they stamp into the tree is written under that umask too.
	runInWithPath(t, dir, standInPython(t)+":/bin:/usr/bin", betweenBuildAndSend(t))
	if _, err := os.Stat(filepath.Join(dir, "dist-repo", "selfhost.sh")); err != nil {
		t.Fatalf("the publish's own steps left no selfhost.sh in the tree: %v", err)
	}

	tree := filepath.Join(dir, "dist-repo")
	checked := 0
	err := filepath.WalkDir(tree, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		want := fs.FileMode(0o644)
		if entry.IsDir() {
			want = 0o755
		}
		if got := modeOf(t, path); got != want {
			rel, _ := filepath.Rel(dir, path)
			t.Errorf("%s is %o after the publish's own steps, the site needs %o", rel, got, want)
		}
		checked++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 10 {
		t.Fatalf("walked %d entries, the tree was not what the test made", checked)
	}
}

// ------------------------------------------------------- the self-hosted installer

// get.whichports.com/selfhost.sh is the line selfhost/README.md gives. The
// publish writes it into the tree it sends, stamped by release_installer.py
// with the release's tag, read in the public repository's clone, because the
// installer clones the public repository and builds only the commit its tag
// names there (require-public-release.sh).
func TestTheSelfHostedInstallerIsStampedIntoTheTreeSent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("publish.sh is a POSIX shell script")
	}
	dir := t.TempDir()
	buildUnderUmask077(t, dir)
	runInWithPath(t, dir, standInPython(t)+":/bin:/usr/bin", betweenBuildAndSend(t))
	path := filepath.Join(dir, "dist-repo", "selfhost.sh")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no selfhost.sh in the tree sent: %v", err)
	}
	want := "stamped: ../selfhost/release_installer.py --repository /the/public/clone v9.9.9\n"
	if string(got) != want {
		t.Errorf("selfhost.sh holds %q, want the stamper's own output for the release, %q", got, want)
	}
	if mode := modeOf(t, path); mode != 0o644 {
		t.Errorf("selfhost.sh is %o, the site needs 644", mode)
	}
	// The stamper is the one in this repository, run from agent/.
	if _, err := os.Stat("../../selfhost/release_installer.py"); err != nil {
		t.Errorf("the publish runs ../selfhost/release_installer.py from agent/, and it is not there: %v", err)
	}
}

func TestTheRightsAreGivenBeforeTheTreeIsSentAndNotAfter(t *testing.T) {
	between := publishLinesBetweenBuildAndSend(t)
	if !strings.Contains(between, "chmod") {
		t.Errorf("no chmod between the build and the send in publish.sh:\n%s", between)
	}
}

// ------------------------------------------------------------ the live check

// liveCheck returns publish.sh's own live_check function, as text.
func liveCheck(t *testing.T) string {
	t.Helper()
	script := publishSource(t)
	start := strings.Index(script, "live_check() {")
	if start < 0 {
		t.Fatal("publish.sh has no live_check function")
	}
	end := strings.Index(script[start:], "\n}\n")
	if end < 0 {
		t.Fatal("publish.sh's live_check function has no end")
	}
	return script[start : start+end+3]
}

// checkWith runs the live check against a stand-in curl that answers each
// path with the code given for it, 200 for the rest, and "fails" for a curl
// that gets no answer at all. It returns the check's exit code and words.
func checkWith(t *testing.T, codes map[string]string) (int, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("publish.sh is a POSIX shell script")
	}
	bin := t.TempDir()
	var cases strings.Builder
	for path, code := range codes {
		if code == "fails" {
			cases.WriteString("  *" + path + ") printf 000; exit 7 ;;\n")
		} else {
			cases.WriteString("  *" + path + ") printf " + code + "; exit 0 ;;\n")
		}
	}
	fake := "#!/bin/sh\n# the last argument is the address\nfor last; do :; done\ncase \"$last\" in\n" +
		cases.String() + "  *) printf 200 ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", "set -eu\nBASE=https://get.example.com\n"+liveCheck(t)+"\nlive_check")
	cmd.Env = []string{"PATH=" + bin + ":/bin:/usr/bin"}
	out, err := cmd.CombinedOutput()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

func TestTheLiveCheckAsksForEachPathTheInstallerReads(t *testing.T) {
	code, out := checkWith(t, nil)
	if code != 0 {
		t.Fatalf("every path answered 200 and the check failed:\n%s", out)
	}
	for _, path := range []string{"/", "/whichports-signing-public.asc",
		"/deb/dists/stable/InRelease", "/rpm/repodata/repomd.xml", "/selfhost.sh"} {
		if !strings.Contains(out, "https://get.example.com"+path+"\n") {
			t.Errorf("the check did not name %s:\n%s", path, out)
		}
	}
}

func TestA403SaysWhichPathAndThatTheServerMayNotReadIt(t *testing.T) {
	code, out := checkWith(t, map[string]string{"/rpm/repodata/repomd.xml": "403"})
	if code == 0 {
		t.Fatalf("a 403 passed the check:\n%s", out)
	}
	for _, want := range []string{"403 https://get.example.com/rpm/repodata/repomd.xml",
		"may not read it", "755", "644"} {
		if !strings.Contains(out, want) {
			t.Errorf("the check's words lack %q:\n%s", want, out)
		}
	}
}

func TestAMissingSelfHostedInstallerFailsTheCheck(t *testing.T) {
	code, out := checkWith(t, map[string]string{"/selfhost.sh": "404"})
	if code == 0 {
		t.Fatalf("no selfhost.sh on the site passed the check:\n%s", out)
	}
	if !strings.Contains(out, "404 https://get.example.com/selfhost.sh: not in the tree that was sent") {
		t.Errorf("the missing installer is not named:\n%s", out)
	}
}

func TestA404AndNoAnswerAtAllSayWhatTheyAre(t *testing.T) {
	code, out := checkWith(t, map[string]string{
		"/whichports-signing-public.asc": "404",
		"/deb/dists/stable/InRelease":    "fails",
	})
	if code == 0 {
		t.Fatalf("a 404 and no answer passed the check:\n%s", out)
	}
	if !strings.Contains(out, "404 https://get.example.com/whichports-signing-public.asc: not in the tree that was sent") {
		t.Errorf("the 404 is not said as such:\n%s", out)
	}
	if !strings.Contains(out, "no answer from https://get.example.com/deb/dists/stable/InRelease") {
		t.Errorf("no answer is not said as such:\n%s", out)
	}
	if strings.Contains(out, "may not read it") {
		t.Errorf("rights were named where no 403 came back:\n%s", out)
	}
}

func TestTheLiveCheckIsWhatThePublishRuns(t *testing.T) {
	script := publishSource(t)
	if !strings.Contains(script, "\nlive_check ||") {
		t.Error("publish.sh does not run live_check and stop when it fails")
	}
}
