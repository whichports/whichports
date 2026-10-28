// This file is the ufw collector: ufw's configuration read from its own
// files, never by executing ufw. The kernel sections hold what is enforced;
// this section holds what the admin asked ufw for, in ufw's own words. The
// two can disagree, and that disagreement is a finding for the control plane,
// not something the agent smooths over.
package collect

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// ufwTupleMarker starts the lines ufw writes into user.rules for each rule
// the admin added: "### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in"
// (observed verbatim on Ubuntu 26.04, 2026-08-12). The tuple is the admin's
// rule in ufw's own normal form, which makes it the honest thing to quote.
const ufwTupleMarker = "### tuple ###"

// CollectUfw reads ufw's state under root (normally "/"). Four files, each
// with its own verdict: /etc/ufw/ufw.conf (ENABLED lives here),
// /etc/default/ufw (the default policies, including forward), and the
// user.rules and user6.rules files whose tuple lines are the rule list. v4
// and v6 are separate files on disk and stay separate in the document.
func CollectUfw(root string) *hostdoc.UfwSection {
	sec := &hostdoc.UfwSection{Sources: map[string]hostdoc.Section{}}

	conf, v := readKeyValueFile(filepath.Join(root, "etc/ufw/ufw.conf"))
	sec.Sources["ufw.conf"] = v
	sec.Conf = conf

	defaults, v := readKeyValueFile(filepath.Join(root, "etc/default/ufw"))
	sec.Sources["default"] = v
	sec.Defaults = defaults

	rules, v := readUfwTuples(filepath.Join(root, "etc/ufw/user.rules"))
	sec.Sources["user.rules"] = v
	sec.Rules = rules

	rules6, v := readUfwTuples(filepath.Join(root, "etc/ufw/user6.rules"))
	sec.Sources["user6.rules"] = v
	sec.Rules6 = rules6

	sec.Section = aggregateSources(sec.Sources)
	return sec
}

// readKeyValueFile reads a KEY=VALUE file of the shape ufw and firewalld use
// for their conf files: comments on #, blank lines ignored, values optionally
// quoted. Keys and values are sanitized. A file whose data lines are all
// unparseable is a parse failure, the same posture as the sockets collector:
// garbage must never read as an empty success.
// ufwFileLimit caps what this collector will read from one file. ufw's conf
// and rules files are kilobytes and anything past this is not one of them.
//
// It exists because these two reads were the only unbounded ones in the
// package, which the 2026-08-15 security review flagged and nobody closed. The
// content is root-owned config, so this is robustness rather than a way in,
// but a collector that reads whatever it is handed is the odd one out beside
// firewalld's zone limit and the container response limit.
const ufwFileLimit = 1 << 20

// readCapped reads at most ufwFileLimit bytes, and refuses a larger file
// rather than truncating it. Truncation would hand the parsers half a config
// and let them report a confident answer about it, which for this product is
// worse than saying the read failed.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	content, err := io.ReadAll(io.LimitReader(f, ufwFileLimit+1))
	if err != nil {
		return nil, err
	}
	if len(content) > ufwFileLimit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, ufwFileLimit)
	}
	return content, nil
}

func readKeyValueFile(path string) (map[string]string, hostdoc.Section) {
	content, err := readCapped(path)
	if err != nil {
		return nil, fileVerdict(err)
	}
	out := map[string]string{}
	dataLines, parsedLines := 0, 0
	sc := bufio.NewScanner(strings.NewReader(string(content)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		dataLines++
		key, val, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) == "" {
			continue
		}
		parsedLines++
		val = strings.TrimSpace(val)
		// Strip one pair of matching quotes: DEFAULT_INPUT_POLICY="DROP".
		if len(val) >= 2 && (val[0] == '"' && val[len(val)-1] == '"' ||
			val[0] == '\'' && val[len(val)-1] == '\'') {
			val = val[1 : len(val)-1]
		}
		out[sanitizeName(strings.TrimSpace(key))] = sanitizeName(val)
	}
	if err := sc.Err(); err != nil {
		return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	}
	if dataLines > 0 && parsedLines == 0 {
		return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	}
	return out, hostdoc.Section{Status: hostdoc.StatusCollected}
}

// readUfwTuples extracts the tuple lines from a ufw rules file, in file
// order, verbatim and sanitized. A rules file with no tuple lines is normal,
// a fresh ufw has chains but no user rules, so unlike the key-value reader
// this one treats "nothing found" as a healthy read.
func readUfwTuples(path string) ([]string, hostdoc.Section) {
	content, err := readCapped(path)
	if err != nil {
		return nil, fileVerdict(err)
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(content)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, found := strings.CutPrefix(line, ufwTupleMarker); found {
			out = append(out, sanitizeName(strings.TrimSpace(rest)))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	}
	return out, hostdoc.Section{Status: hostdoc.StatusCollected}
}

// fileVerdict maps a file read error to a typed per-source verdict.
func fileVerdict(err error) hostdoc.Section {
	switch {
	case os.IsNotExist(err):
		return hostdoc.Section{Status: hostdoc.StatusNotPresent}
	case os.IsPermission(err):
		return hostdoc.Section{Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission}
	default:
		return hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	}
}

// aggregateSources derives a section-level verdict from per-source verdicts,
// the same rules the sockets collector established (RECORD.md 4.17): any one
// healthy source makes the section collected and the map carries the rest,
// permission outranks parse failure when nothing collected, and all-absent
// means the whole subsystem is not present on this host.
func aggregateSources(sources map[string]hostdoc.Section) hostdoc.Section {
	anyCollected, anyPerm, anyFailed := false, false, false
	for _, s := range sources {
		switch s.Status {
		case hostdoc.StatusCollected:
			anyCollected = true
		case hostdoc.StatusPermissionDenied:
			anyPerm = true
			anyFailed = true
		case hostdoc.StatusReadError:
			anyFailed = true
		}
	}
	switch {
	case anyCollected:
		return hostdoc.Section{Status: hostdoc.StatusCollected}
	case anyPerm:
		return hostdoc.Section{Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission}
	case anyFailed:
		return hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	default:
		return hostdoc.Section{Status: hostdoc.StatusNotPresent}
	}
}
