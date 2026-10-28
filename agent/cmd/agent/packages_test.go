package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// A root that holds dpkg's records and a listening service give a section
// that read those records and names the unit, and the report carries the
// key. Until 2026-10-12 this was the half of a pair: a build without the
// readers' tag returned no section and sent no key
// (docs/SPEC-packages-switch.md).
func TestAReportHasThePackagesKey(t *testing.T) {
	section := collectPackages(dpkgRoot(t), listeningApp(), nil, "")
	if section == nil {
		t.Fatal("the agent returned no packages section")
	}
	for _, source := range []string{"dpkg_status", "dpkg_info"} {
		if got := section.Sources[source].Status; got != hostdoc.StatusCollected {
			t.Errorf("%s read %q on a root that holds it, want collected", source, got)
		}
	}
	if len(section.Units) != 1 || section.Units[0].Unit != "app.service" {
		t.Fatalf("the listening service is not in the section: %+v", section.Units)
	}
	// And the whole document, as every mode sends it. This machine may have
	// no dpkg at all, and the key is there all the same, with its status.
	if _, has := stdoutDocument(t)["packages"]; !has {
		t.Fatal("the report carries no packages key")
	}
}

// aptRoot is dpkgRoot with apt's folder in it: Debian's own archive, whose
// one list offers a newer version of the package behind the listening
// service.
func aptRoot(t *testing.T) string {
	t.Helper()
	root := dpkgRoot(t)
	lists := filepath.Join(root, "var/lib/apt/lists")
	if err := os.MkdirAll(lists, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"deb.debian.org_debian_dists_bookworm_InRelease":                  "Origin: Debian\nLabel: Debian\nCodename: bookworm\nMD5Sum:\n 00 1 main/binary-amd64/Packages\n",
		"deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages": "Package: app\nVersion: 1.1\nArchitecture: amd64\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(lists, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// everyFile is every path under the given folders with its size, its time
// and its mode, so two of them compared say exactly what a run wrote.
func everyFile(t *testing.T, dirs ...string) map[string]string {
	t.Helper()
	seen := map[string]string{}
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			seen[path] = fmt.Sprintf("%d bytes, %d, %v", info.Size(), info.ModTime().UnixNano(), info.Mode())
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return seen
}

func offeredVersions(section *hostdoc.PackagesSection) []string {
	var out []string
	for _, entry := range section.Offers {
		for _, offer := range entry.Offered {
			out = append(out, entry.Name+" "+offer.Archive+" "+offer.Version)
		}
	}
	return out
}

// The agent reads a host and writes one thing there: its own state. With the
// lists reader that is one file more, beside the state file, and nothing
// else. Not in apt's folder, not in dpkg's, not anywhere under the root.
func TestTheReaderWritesOnlyItsOwnKeptFile(t *testing.T) {
	root, state := aptRoot(t), t.TempDir()
	kept := filepath.Join(state, keptListsName)
	before := everyFile(t, root, state)

	section := collectPackages(root, listeningApp(), nil, kept)
	if got, want := offeredVersions(section), []string{"app debian 1.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("the lists were not read, so nothing here says what the reader writes: offers %v, want %v", got, want)
	}
	after := everyFile(t, root, state)
	for path, is := range after {
		if was, had := before[path]; path != kept && path != state && (!had || was != is) {
			t.Errorf("the run wrote %s: %q, was %q", path, is, was)
		}
	}
	for path := range before {
		if _, still := after[path]; !still {
			t.Errorf("the run removed %s", path)
		}
	}
	info, err := os.Lstat(kept)
	if err != nil {
		t.Fatalf("the reader kept nothing: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != stateFileMode {
		t.Errorf("the kept file is %v, want a regular file of mode %o like the state file", info.Mode(), stateFileMode)
	}

	// A second run on lists that did not change writes nothing at all, the
	// kept file included: it holds what it held.
	again := collectPackages(root, listeningApp(), nil, kept)
	if !reflect.DeepEqual(offeredVersions(again), offeredVersions(section)) {
		t.Errorf("the second run offers %v, the first %v", offeredVersions(again), offeredVersions(section))
	}
	if now := everyFile(t, root, state); !reflect.DeepEqual(now, after) {
		t.Errorf("the second run wrote something:\n%v\n%v", after, now)
	}
}

// stdout and oneshot name no place to keep anything, and then nothing is
// written anywhere.
func TestWithNoPlaceToKeepItTheReaderWritesNothing(t *testing.T) {
	root, state := aptRoot(t), t.TempDir()
	before := everyFile(t, root, state)
	section := collectPackages(root, listeningApp(), nil, "")
	if len(offeredVersions(section)) != 1 {
		t.Fatalf("the lists were not read: %+v", section.Offers)
	}
	if after := everyFile(t, root, state); !reflect.DeepEqual(after, before) {
		t.Errorf("a run with no place to keep anything wrote something:\n%v\n%v", before, after)
	}
}

// A link where the kept file belongs is not read through and not written
// through. What it points at stays as it was, and the lists are read.
func TestAKeptFileThatIsALinkIsNeitherReadNorWrittenThrough(t *testing.T) {
	root, state, elsewhere := aptRoot(t), t.TempDir(), t.TempDir()
	// Somebody else's file, holding what a kept file of the reader's own
	// shape would hold, with a version the lists do not offer.
	theirs := filepath.Join(elsewhere, "theirs.json")
	first := filepath.Join(state, "first.json")
	collectPackages(root, listeningApp(), nil, first)
	honest, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	forged := []byte(string(honest[:len(honest)-len(`1.1","architecture":"amd64"}]}]}`)]) + `9.9","architecture":"amd64"}]}]}`)
	if err := os.WriteFile(theirs, forged, 0o644); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(state, keptListsName)
	if err := os.Symlink(theirs, kept); err != nil {
		t.Fatal(err)
	}

	section := collectPackages(root, listeningApp(), nil, kept)
	if got, want := offeredVersions(section), []string{"app debian 1.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("offers %v, want the lists' own %v: the link was read through", got, want)
	}
	if now, _ := os.ReadFile(theirs); string(now) != string(forged) {
		t.Errorf("the file the link points at was written:\n%s", now)
	}
	if info, err := os.Lstat(kept); err != nil || !info.Mode().IsRegular() {
		t.Errorf("the kept file is not a file of the reader's own after the run: %v %v", info, err)
	}
}

// A kept file that cannot be written costs the next run a read of the lists
// and nothing else. The report is whole.
func TestAKeptFileThatCannotBeWrittenDoesNotFailTheReport(t *testing.T) {
	root := aptRoot(t)
	kept := filepath.Join(t.TempDir(), "no-such-folder", keptListsName)
	section := collectPackages(root, listeningApp(), nil, kept)
	if got, want := offeredVersions(section), []string{"app debian 1.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("offers %v, want %v", got, want)
	}
}

// The kept file's place is beside the state file, in the folder the
// packaged unit may write (ReadWritePaths in whichports-agent.service).
func TestTheKeptFileIsBesideTheStateFile(t *testing.T) {
	if got, want := keptListsPath("/var/lib/whichports/host.json"), "/var/lib/whichports/apt-lists.json"; got != want {
		t.Errorf("the kept file is %s, want %s", got, want)
	}
}
