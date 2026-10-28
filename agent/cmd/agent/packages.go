package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/whichports/whichports/agent/internal/collect"
	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// keptListsName is the one other file the agent writes, beside the state file
// and only in timer mode: what the apt lists reader read, so a list that did
// not change is not read again at the next report. It never leaves the host.
const keptListsName = "apt-lists.json"

// keptListsPath is where the kept file stands for a given state file: the
// same folder, the one the packaged unit may write.
func keptListsPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), keptListsName)
}

// maxKeptListsBytes bounds what is read back of the kept file. On the lists
// of a Debian 12 and of an Ubuntu 24.04 install the file was 1301 and 2934
// bytes, for three packages (read on 2026-10-09).
//
// The collector's own caps allow far more than this bound: 256 packages
// (hostdoc.MaxOfferPackages), and of each as many as 4096 versions in every
// list (maxVersionsPerList in internal/collect/aptlists.go). So a host whose
// archives hold thousands of versions of a package can come to keep a file
// past it. Such a file is written and then not read back, which costs that
// host a read of every list at every run and nothing else.
const maxKeptListsBytes = 8 << 20

// collectPackages reads what dpkg's records say about each service behind a
// listening socket, and what the host's apt lists offer for the packages
// those records name (internal/collect/packages.go and aptlists.go).
//
// keptLists is the file the lists reader's last read is kept in, or empty.
// The agent's process ends after each report, so without that file every
// list would be read again every time, a hundred megabytes on a server read
// on 2026-10-07 (docs/RECORD.md 4.430). With it a list is opened only when
// its size or its time changed. Only timer mode names the file: the other
// two modes write nothing on a host and stay that way.
func collectPackages(root string, sockets *hostdoc.SocketsSection, socketUnits *hostdoc.SocketUnitsSection, keptLists string) *hostdoc.PackagesSection {
	units := collect.ListeningServiceUnits(sockets, socketUnits)
	if keptLists == "" {
		return collect.CollectPackages(root, units)
	}
	was := readKeptLists(keptLists)
	section, keep := collect.CollectPackagesKeeping(root, units, was)
	// Written only when it is not what is there already, so a host whose
	// lists stand still gets no write at all. A write that fails costs the
	// next run a read of the lists and nothing else, so it does not fail
	// the report: the state file is written to the same folder right after
	// this, and a folder that cannot be written fails the run there.
	if keep != nil && !bytes.Equal(keep, was) {
		_ = writeFileAtomic(keptLists, keep)
	}
	return section
}

// readKeptLists returns the kept file's bytes, or nil when there is no file
// of the reader's own to read: none at all, a link, anything that is not a
// regular file, or one past its cap. A link is not followed, so the reader
// never takes its answer from a file somebody pointed it at. What the bytes
// are worth is the collector's to judge (collect.CollectPackagesKeeping).
func readKeptLists(path string) []byte {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxKeptListsBytes {
		return nil
	}
	kept, err := io.ReadAll(io.LimitReader(f, maxKeptListsBytes+1))
	if err != nil || len(kept) > maxKeptListsBytes {
		return nil
	}
	return kept
}
