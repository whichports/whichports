// The --version path answers "what binary is this" and does nothing else.
// It exists because a published package once had to be traced by unpacking
// it and reading the Go buildinfo by hand (docs/RECORD.md 4.63), when one
// flag would have answered the same question on the box.
//
// The path is deliberately confined to this file, whose only imports are
// fmt, io and runtime/debug: no os, no net, no collector package. Printing
// the version therefore cannot read /proc, open a file or touch the network,
// and TestVersionFileImportsOnlyHarmlessPackages keeps that true the same
// way internal/safety keeps exec and listen out of the agent.
package main

import (
	"fmt"
	"io"
	"runtime/debug"
)

// version is the package version, injected by the Makefile with
// -ldflags "-X main.version=$(PKG_VERSION)", the same value nfpm stamps on
// the .deb and .rpm, so the binary and the package that ships it always name
// one version. A plain `go build` leaves it empty and the line says unknown
// rather than guessing.
var version string

// printVersion writes the one line --version produces. Reading the build
// info is a memory read of what the toolchain embedded in the binary at
// build time, not a file read.
func printVersion(out io.Writer) {
	info, _ := debug.ReadBuildInfo()
	fmt.Fprintln(out, versionLine(version, info))
}

// versionLine formats the line from the injected package version and the
// toolchain's embedded build info. The vcs keys are printed under their
// buildinfo names, because those are the names an operator sees when they
// inspect the binary with `go version -m` and the names docs/RECORD.md 4.63
// used to trace the 0.1.6. Every field the build did not record says
// unknown, never a guess: a binary built outside git, or with buildvcs off,
// simply has no vcs settings to report.
func versionLine(pkgVersion string, info *debug.BuildInfo) string {
	const unknown = "unknown"
	revision, vcsTime, modified := unknown, unknown, unknown
	if info != nil {
		for _, s := range info.Settings {
			if s.Value == "" {
				continue
			}
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.time":
				vcsTime = s.Value
			case "vcs.modified":
				modified = s.Value
			}
		}
	}
	if pkgVersion == "" {
		pkgVersion = unknown
	}
	return fmt.Sprintf("whichports-agent version=%s vcs.revision=%s vcs.time=%s vcs.modified=%s",
		pkgVersion, revision, vcsTime, modified)
}
