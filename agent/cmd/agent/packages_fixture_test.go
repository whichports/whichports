package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// What the package tests share: a root that holds dpkg's records and one
// listening service whose program a package owns.

// dpkgRoot is a file tree with a dpkg database in it: one installed package,
// its file list, its unit file and its program.
func dpkgRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/os-release", "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n")
	write("usr/lib/systemd/system/app.service", "[Service]\nExecStart=/usr/bin/app\n")
	write("usr/bin/app", "\x7fELF")
	write("var/lib/dpkg/status",
		"Package: app\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n")
	write("var/lib/dpkg/info/app.list",
		"/.\n/usr/bin/app\n/usr/lib/systemd/system/app.service\n")
	return root
}

// listeningApp is a socket section in which app.service holds a listening
// socket, which is what makes the reader look the unit up at all.
func listeningApp() *hostdoc.SocketsSection {
	return &hostdoc.SocketsSection{
		Section: hostdoc.Section{Status: hostdoc.StatusCollected},
		Listening: []hostdoc.ListeningSocket{{
			Protocol: "tcp", Family: "v4", BindAddress: "0.0.0.0", Port: 8080,
			Unit: "app.service", Cgroup: "/system.slice/app.service",
		}},
	}
}

// stdoutDocument is the document stdout mode prints on this machine, as its
// top-level keys. The raw keys are read, because a field that is absent and
// one that is null look the same once decoded into a struct.
func stdoutDocument(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	configPath, statePath := paths(t)
	var buf bytes.Buffer
	if err := run("stdout", &buf, 12345, configPath, statePath); err != nil {
		t.Fatalf("stdout mode failed: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("stdout mode must print valid JSON: %v\n%s", err, buf.String())
	}
	if _, has := doc["schema_version"]; !has {
		t.Fatalf("this is not a host document:\n%s", buf.String())
	}
	return doc
}
