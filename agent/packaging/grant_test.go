package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The installer's grant function, run for real against a tree on disk.
//
// install_test.go reads the installer as text, which is enough for a constant
// and not for this. Stock Fedora 44 could not install because grant refused a
// link firewalld's own package ships (docs/RECORD.md 4.223), and whether a
// link is followed, and to where, is something only running the function
// answers. setfacl is a stub that records what it was asked for: handing a
// file to another user needs root and a real account, and the question here
// is which path the function chose, not what setfacl then does with it.

// grantFunction cuts grant() out of install.sh, from its first line to the
// closing brace at the start of a line.
func grantFunction(t *testing.T) string {
	t.Helper()
	script := installerSource(t)
	start := strings.Index(script, "\ngrant() {\n")
	if start < 0 {
		t.Fatal("install.sh has no grant() function, so the installer has changed " +
			"shape and these tests must be updated to match")
	}
	rest := script[start+1:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatal("could not find the end of grant() in install.sh")
	}
	return rest[:end+3]
}

// runGrant calls grant with perms and paths, under the installer's own
// `set -eu`. It returns what setfacl was asked for, one call per line, the
// combined output, and the run error.
func runGrant(t *testing.T, perms string, paths ...string) (string, string, error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the installer is a POSIX shell script")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "setfacl.log")
	stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + shellQuote(log) + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "setfacl"), []byte(stub), 0o755); err != nil {
		t.Fatalf("writing the setfacl stub: %v", err)
	}

	call := "grant " + perms
	for _, path := range paths {
		call += " " + shellQuote(path)
	}
	script := "set -eu\n" + grantFunction(t) + call + "\necho reached-the-end\n"
	scriptPath := filepath.Join(dir, "grant.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(), "PATH="+dir+":/bin:/usr/bin")
	out, runErr := cmd.CombinedOutput()

	data, err := os.ReadFile(log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("reading the setfacl log: %v", err)
	}
	return string(data), string(out), runErr
}

// realDir is a temp directory by the name the kernel resolves it to. On
// macOS the temp directory is reached through a link, and the paths asserted
// below are the resolved ones.
func realDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// An ordinary file, which is every target on Debian, Ubuntu, AlmaLinux and
// Rocky: granted by its own name, and nothing about a link is said.
func TestGrantOnAPlainFile(t *testing.T) {
	dir := realDir(t)
	conf := filepath.Join(dir, "firewalld.conf")
	writeFile(t, conf)

	calls, out, err := runGrant(t, "r", conf)
	if err != nil {
		t.Fatalf("grant failed on a plain file: %v\n%s", err, out)
	}
	if want := "-m u:whichports-agent:r " + conf + "\n"; calls != want {
		t.Errorf("setfacl was asked for %q, want %q", calls, want)
	}
	if strings.Contains(out, "link") {
		t.Errorf("a plain file was described as a link:\n%s", out)
	}
}

// Fedora 44, as its package ships it: firewalld.conf is a relative link to
// firewalld-standard.conf in the same directory. The install has to go on,
// and the grant has to land on the file that holds the configuration.
func TestGrantFollowsFirewalldsOwnPackagedLink(t *testing.T) {
	dir := realDir(t)
	standard := filepath.Join(dir, "firewalld-standard.conf")
	writeFile(t, standard)
	writeFile(t, filepath.Join(dir, "firewalld-server.conf"))
	conf := filepath.Join(dir, "firewalld.conf")
	symlink(t, "firewalld-standard.conf", conf)

	calls, out, err := runGrant(t, "r", conf)
	if err != nil {
		t.Fatalf("grant stopped the installer on firewalld's own link, which is "+
			"the fault of docs/RECORD.md 4.223: %v\n%s", err, out)
	}
	if want := "-m u:whichports-agent:r " + standard + "\n"; calls != want {
		t.Errorf("setfacl was asked for %q, want the grant on the file the link "+
			"resolves to, %q", calls, want)
	}
	if !strings.Contains(out, "reached-the-end") {
		t.Errorf("the script did not carry on after the grant:\n%s", out)
	}
	if !strings.Contains(out, conf) || !strings.Contains(out, standard) {
		t.Errorf("the output does not name both the link and the file it granted on:\n%s", out)
	}
}

// The same link written with an absolute target, and a chain of two links
// that never leaves the directory. Both end at a file beside the link.
func TestGrantFollowsOtherLinksThatStayInTheDirectory(t *testing.T) {
	t.Run("an absolute target", func(t *testing.T) {
		dir := realDir(t)
		standard := filepath.Join(dir, "firewalld-standard.conf")
		writeFile(t, standard)
		conf := filepath.Join(dir, "firewalld.conf")
		symlink(t, standard, conf)

		calls, out, err := runGrant(t, "r", conf)
		if err != nil {
			t.Fatalf("grant refused a link to a file beside it: %v\n%s", err, out)
		}
		if want := "-m u:whichports-agent:r " + standard + "\n"; calls != want {
			t.Errorf("setfacl was asked for %q, want %q", calls, want)
		}
	})

	t.Run("a chain of two links", func(t *testing.T) {
		dir := realDir(t)
		standard := filepath.Join(dir, "firewalld-standard.conf")
		writeFile(t, standard)
		middle := filepath.Join(dir, "firewalld-current.conf")
		symlink(t, "firewalld-standard.conf", middle)
		conf := filepath.Join(dir, "firewalld.conf")
		symlink(t, "firewalld-current.conf", conf)

		calls, out, err := runGrant(t, "r", conf)
		if err != nil {
			t.Fatalf("grant refused a chain that stays in the directory: %v\n%s", err, out)
		}
		if want := "-m u:whichports-agent:r " + standard + "\n"; calls != want {
			t.Errorf("setfacl was asked for %q, want the end of the chain, %q", calls, want)
		}
	})

	t.Run("a directory that is itself reached through a link", func(t *testing.T) {
		// The link's directory is compared in its resolved form, so a host
		// whose /etc is reached through a link is not refused for that.
		dir := realDir(t)
		real := filepath.Join(dir, "real-etc-firewalld")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		standard := filepath.Join(real, "firewalld-standard.conf")
		writeFile(t, standard)
		symlink(t, "firewalld-standard.conf", filepath.Join(real, "firewalld.conf"))
		through := filepath.Join(dir, "etc-firewalld")
		symlink(t, real, through)

		calls, out, err := runGrant(t, "r", filepath.Join(through, "firewalld.conf"))
		if err != nil {
			t.Fatalf("grant refused a link beside its file because the directory "+
				"is reached through a link: %v\n%s", err, out)
		}
		if want := "-m u:whichports-agent:r " + standard + "\n"; calls != want {
			t.Errorf("setfacl was asked for %q, want %q", calls, want)
		}
	})
}

// Every other link still stops the installer, and grants nothing through it.
// setfacl follows a link (setfacl(1)), so a link out of the directory would
// hand the agent's user read on whatever it names.
func TestGrantRefusesALinkThatIsNotToAFileBesideIt(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, dir string) (link string, victim string)
	}{
		{"a file in another directory", func(t *testing.T, dir string) (string, string) {
			other := filepath.Join(dir, "elsewhere")
			if err := os.Mkdir(other, 0o755); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(other, "shadow")
			writeFile(t, victim)
			link := filepath.Join(dir, "firewalld.conf")
			symlink(t, victim, link)
			return link, victim
		}},
		{"a file in the parent directory, by a relative name", func(t *testing.T, dir string) (string, string) {
			inner := filepath.Join(dir, "firewalld")
			if err := os.Mkdir(inner, 0o755); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(dir, "shadow")
			writeFile(t, victim)
			link := filepath.Join(inner, "firewalld.conf")
			symlink(t, "../shadow", link)
			return link, victim
		}},
		{"a file in a directory below", func(t *testing.T, dir string) (string, string) {
			below := filepath.Join(dir, "zones")
			if err := os.Mkdir(below, 0o755); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(below, "public.xml")
			writeFile(t, victim)
			link := filepath.Join(dir, "firewalld.conf")
			symlink(t, "zones/public.xml", link)
			return link, victim
		}},
		{"a chain that ends in another directory", func(t *testing.T, dir string) (string, string) {
			other := filepath.Join(dir, "elsewhere")
			if err := os.Mkdir(other, 0o755); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(other, "shadow")
			writeFile(t, victim)
			middle := filepath.Join(dir, "firewalld-current.conf")
			symlink(t, victim, middle)
			link := filepath.Join(dir, "firewalld.conf")
			symlink(t, "firewalld-current.conf", link)
			return link, victim
		}},
		{"a directory beside it", func(t *testing.T, dir string) (string, string) {
			victim := filepath.Join(dir, "a-directory")
			if err := os.Mkdir(victim, 0o755); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, "zones")
			symlink(t, "a-directory", link)
			return link, victim
		}},
		{"nothing at all", func(t *testing.T, dir string) (string, string) {
			link := filepath.Join(dir, "firewalld.conf")
			symlink(t, "firewalld-standard.conf", link)
			return link, filepath.Join(dir, "firewalld-standard.conf")
		}},
		{"itself", func(t *testing.T, dir string) (string, string) {
			link := filepath.Join(dir, "firewalld.conf")
			symlink(t, "firewalld.conf", link)
			return link, link
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := realDir(t)
			link, victim := tc.build(t, dir)

			calls, out, err := runGrant(t, "r", link)
			if err == nil {
				t.Errorf("grant carried on over a link to %s:\n%s", tc.name, out)
			}
			if calls != "" {
				t.Errorf("setfacl was called although the link was to %s (%s):\n%s",
					tc.name, victim, calls)
			}
			if strings.Contains(out, "reached-the-end") {
				t.Errorf("the installer carried on after the refusal:\n%s", out)
			}
			if !strings.Contains(out, "refusing: "+link) {
				t.Errorf("the refusal does not name the link:\n%s", out)
			}
			// The old refusal told the operator to remove the link, which
			// on Fedora meant removing firewalld's own configuration.
			if strings.Contains(strings.ToLower(out), "remove the link") {
				t.Errorf("the refusal still advises removing the link:\n%s", out)
			}
		})
	}
}

// A refusal stops the whole run where it stands: the files before the link
// are granted, the ones after it are not, and the script never reaches its
// next line. Carrying on would end an install that looks finished with a
// Rules tab that reads "not readable" and nothing saying why.
func TestGrantStopsAtTheFirstRefusal(t *testing.T) {
	dir := realDir(t)
	other := filepath.Join(dir, "elsewhere")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(other, "shadow")
	writeFile(t, outside)

	first := filepath.Join(dir, "first.xml")
	writeFile(t, first)
	bad := filepath.Join(dir, "bad.xml")
	symlink(t, outside, bad)
	last := filepath.Join(dir, "last.xml")
	writeFile(t, last)

	calls, out, err := runGrant(t, "r", first, bad, last)
	if err == nil {
		t.Fatalf("grant carried on past a refused link:\n%s", out)
	}
	if want := "-m u:whichports-agent:r " + first + "\n"; calls != want {
		t.Errorf("setfacl was asked for %q, want only the file before the link, %q", calls, want)
	}
}

// A zone file may carry a space in its name, and the directory grant is rx
// rather than r. Neither may change which path setfacl is handed.
func TestGrantPassesNamesAndPermissionsThrough(t *testing.T) {
	dir := realDir(t)
	zone := filepath.Join(dir, "my zone.xml")
	writeFile(t, zone)

	calls, out, err := runGrant(t, "rx", dir, zone)
	if err != nil {
		t.Fatalf("grant failed: %v\n%s", err, out)
	}
	want := "-m u:whichports-agent:rx " + dir + "\n" +
		"-m u:whichports-agent:rx " + zone + "\n"
	if calls != want {
		t.Errorf("setfacl was asked for %q, want %q", calls, want)
	}
}
