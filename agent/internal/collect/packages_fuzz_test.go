package collect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// The fuzz targets of the package reader (packages.go). They are built with
// the reader, under the same tag, and were in fuzz_test.go until the reader
// went behind it (docs/RECORD.md 4.385).

func FuzzExecStartProgram(f *testing.F) {
	// A unit file is host-written text and the program path it yields goes on
	// the wire. Whatever the parser accepts must be one plain absolute path,
	// and must survive the marshaller as a program.
	f.Add("[Service]\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS\n")
	f.Add("[Service]\nExecStart=\nExecStart=-/usr/bin/x\n[Unit]\nExecStart=/y\n")
	f.Add("[Service]\nExecStart=/a \\\n ; /b\n")
	f.Add("[Service\nExecStart=\x00\xff\x1b[31m\n")
	f.Fuzz(func(t *testing.T, content string) {
		finding, program := execStartProgram(content)
		if !hostdocFinding(finding) {
			t.Fatalf("finding %q is not one of the closed list", finding)
		}
		if (finding == "complete") != (program != "") {
			t.Fatalf("finding %q with program %q", finding, program)
		}
		if program == "" {
			return
		}
		if !plainAbsolutePath(program) {
			t.Fatalf("returned %q, which is not a plain absolute path", program)
		}
		if !pathWithinCap(program) {
			return // the collector cuts it before it reaches the document
		}
		marshalOrFail(t, func(d *hostdoc.Document) {
			d.Packages = &hostdoc.PackagesSection{
				Section: hostdoc.Section{Status: hostdoc.StatusCollected},
				Units: []hostdoc.UnitPackage{{Unit: "a.service", Finding: "complete",
					UnitFile:    &hostdoc.OwnedPath{Path: "/usr/lib/systemd/system/a.service"},
					Program:     &hostdoc.OwnedPath{Path: sanitizeName(program)},
					ProgramKind: "elf"}},
			}
		})
	})
}

func hostdocFinding(f string) bool {
	for _, v := range hostdoc.UnitPackageFindings {
		if v == f {
			return true
		}
	}
	return false
}

func FuzzDpkgFiles(f *testing.F) {
	// The status file, a file list and the diversions file are host-written
	// bytes. Whatever they say, the collector must not panic and its section
	// must survive the marshaller.
	f.Add("Package: app\nStatus: install ok installed\nArchitecture: arm64\nSource: app (1.0)\nVersion: 1.0+b1\n",
		"/.\n/usr/bin/app\n", "/usr/bin/app\n/usr/bin/app.distrib\n:\n")
	f.Add("Package: app\nStatus: half\nVersion: \x1b[31m\nSource: x (\n\n\nPackage:\n", "\x00\n/usr/bin/app", "a\nb\n")
	f.Fuzz(func(t *testing.T, status, list, diversions string) {
		root := t.TempDir()
		write := func(rel, content string) {
			p := filepath.Join(root, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write("usr/lib/systemd/system/app.service", "[Service]\nExecStart=/usr/bin/app\n")
		write("usr/bin/app", "\x7fELF")
		write("var/lib/dpkg/status", status)
		write("var/lib/dpkg/info/app.list", list)
		write("var/lib/dpkg/diversions", diversions)
		sec := CollectPackages(root, []string{"app.service"})
		marshalOrFail(t, func(d *hostdoc.Document) { d.Packages = sec })
	})
}
