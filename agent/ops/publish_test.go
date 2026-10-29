package ops

import (
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// publish.sh sends the signed repository tree to the machine that serves
// get.whichports.com, with `rsync --delete`. These tests hold two things
// about where it sends it.
//
// The script names the machine by an ssh alias and never by an address. This
// directory is readable source, and an address or a login written into it is
// a fact about one person's server that every reader then holds.
//
// And the destination can never come out with no host in front of the colon,
// because the rsync that follows deletes whatever is not in the tree.

func publishSource(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("publish.sh")
	if err != nil {
		t.Fatalf("reading publish.sh: %v", err)
	}
	return string(data)
}

func TestPublishNamesNoAddressAndNoLogin(t *testing.T) {
	script := publishSource(t)
	if found := regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`).FindAllString(script, -1); len(found) > 0 {
		t.Errorf("publish.sh carries an IPv4 address, %v. Name the machine by its ssh alias", found)
	}
	// user@host: in front of a path is an rsync or scp destination with the
	// login written out. The signing identity is an email address and has no
	// colon after it, so it does not match.
	if found := regexp.MustCompile(`[A-Za-z0-9_.-]+@[A-Za-z0-9_.\[\]:-]+:/`).FindAllString(script, -1); len(found) > 0 {
		t.Errorf("publish.sh carries a login and a host, %v. Both belong in ~/.ssh/config", found)
	}
}

// publishDestination evaluates the script's own HOST= and DEST= lines under
// the script's own `set -eu`, with env added to an otherwise empty
// environment, and returns what DEST comes out as.
func publishDestination(t *testing.T, env ...string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("publish.sh is a POSIX shell script")
	}
	var lines []string
	for _, name := range []string{"HOST=", "DEST="} {
		var found []string
		for _, line := range strings.Split(publishSource(t), "\n") {
			if strings.HasPrefix(line, name) {
				found = append(found, line)
			}
		}
		if len(found) != 1 {
			t.Fatalf("publish.sh has %d lines starting with %s, want exactly one: %v",
				len(found), name, found)
		}
		lines = append(lines, found[0])
	}
	snippet := "set -eu\n" + strings.Join(lines, "\n") + "\nprintf '%s' \"$DEST\"\n"
	cmd := exec.Command("sh", "-c", snippet)
	cmd.Env = append([]string{"PATH=/bin:/usr/bin"}, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("evaluating the destination failed: %v\n%s", err, out)
	}
	return string(out)
}

func TestPublishGoesToTheAliasUnlessToldOtherwise(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"nothing set", nil, "whichports:/srv/get.whichports.com/"},
		{"another machine for one run", []string{"WHICHPORTS_HOST=staging-box"},
			"staging-box:/srv/get.whichports.com/"},
		// A variable that is set and empty must not leave ":/srv/..." behind.
		{"an override that is empty", []string{"WHICHPORTS_HOST="},
			"whichports:/srv/get.whichports.com/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := publishDestination(t, tc.env...); got != tc.want {
				t.Errorf("the destination is %q, want %q", got, tc.want)
			}
		})
	}
}

// The destination line is only worth testing if it is the one rsync is given.
func TestPublishSendsTheTreeToThatDestination(t *testing.T) {
	script := publishSource(t)
	var rsyncs []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "rsync ") {
			rsyncs = append(rsyncs, strings.TrimSpace(line))
		}
	}
	if len(rsyncs) != 1 || rsyncs[0] != `rsync -a --delete dist-repo/ "$DEST"` {
		t.Errorf("publish.sh's rsync lines are %q, want exactly one, sending dist-repo/ to \"$DEST\"", rsyncs)
	}
}

// ------------------------------------------------- the public repository's clone

// publishPublic evaluates the script's own PUBLIC= line under its `set -eu`,
// with env added to an environment that has only PATH and HOME.
func publishPublic(t *testing.T, env ...string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("publish.sh is a POSIX shell script")
	}
	var found []string
	for _, line := range strings.Split(publishSource(t), "\n") {
		if strings.HasPrefix(line, "PUBLIC=") {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		t.Fatalf("publish.sh has %d lines starting with PUBLIC=, want exactly one: %v", len(found), found)
	}
	cmd := exec.Command("sh", "-c", "set -eu\n"+found[0]+"\nprintf '%s' \"$PUBLIC\"\n")
	cmd.Env = append([]string{"PATH=/bin:/usr/bin", "HOME=/home/owner"}, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("evaluating PUBLIC failed: %v\n%s", err, out)
	}
	return string(out)
}

func TestPublishReadsThePublicReleaseFromTheOwnersCloneUnlessToldOtherwise(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"nothing set", nil, "/home/owner/whichports-public"},
		{"another clone for one run", []string{"WHICHPORTS_PUBLIC=/elsewhere/public"}, "/elsewhere/public"},
		{"an override that is empty", []string{"WHICHPORTS_PUBLIC="}, "/home/owner/whichports-public"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := publishPublic(t, tc.env...); got != tc.want {
				t.Errorf("the clone is %q, want %q", got, tc.want)
			}
		})
	}
}

// The guard reads the public repository before this commit is tagged, so a
// refusal leaves no tag here and builds nothing. The stamp comes after the
// tree is built, since `make repo` empties dist-repo first.
func TestThePublicReleaseIsCheckedBeforeAnythingIsTaggedOrBuilt(t *testing.T) {
	script := publishSource(t)
	at := func(line string) int {
		t.Helper()
		if n := strings.Count(script, "\n"+line+"\n"); n != 1 {
			t.Fatalf("publish.sh has %d lines %q, want exactly one", n, line)
		}
		return strings.Index(script, "\n"+line+"\n")
	}
	guard := at(`sh ops/require-public-release.sh "$PUBLIC" "$TAG"`)
	tag := at(`  git tag "$TAG"`)
	build := at(`SIGNING_KEY_FILE="$TMPKEY" NFPM_PASSPHRASE="$PASS" make package-signed`)
	repo := at(`SIGNING_KEY_FILE="$TMPKEY" REPO_GPG_PASSPHRASE="$PASS" make repo`)
	stamp := at(`python3 ../selfhost/release_installer.py --repository "$PUBLIC" "$TAG" > dist-repo/selfhost.sh`)
	if !(guard < tag && guard < build) {
		t.Errorf("the public release is checked at %d, after the tag at %d or the build at %d", guard, tag, build)
	}
	if !(repo < stamp) {
		t.Errorf("the installer is stamped at %d, before make repo at %d empties the tree", stamp, repo)
	}
}
