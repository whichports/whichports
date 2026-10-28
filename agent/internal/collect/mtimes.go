// This file is the rule-file mtimes collector: when each firewall
// configuration file last changed, by stat, so "when did this change" has an
// answer before any history exists (docs/PRODUCT.md 4). Stat only: no file is
// opened, no content read.
package collect

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// ruleFilePaths are the fixed rule-file locations this collector checks,
// relative to the filesystem root. The nftables boot ruleset and the ufw
// paths were confirmed live on Ubuntu 26.04 and the RHEL-family nftables path
// on AlmaLinux 10.2 (2026-08-12); the iptables-persistent and
// iptables-services paths are those packages' documented config locations.
// A path that does not exist on a host is simply absent from the output:
// absence of a file is not a finding here, the file list is.
var ruleFilePaths = []string{
	"etc/nftables.conf",
	"etc/sysconfig/nftables.conf",
	"etc/ufw/ufw.conf",
	"etc/default/ufw",
	"etc/ufw/user.rules",
	"etc/ufw/user6.rules",
	"etc/ufw/before.rules",
	"etc/ufw/before6.rules",
	"etc/ufw/after.rules",
	"etc/ufw/after6.rules",
	"etc/firewalld/firewalld.conf",
	"etc/iptables/rules.v4",
	"etc/iptables/rules.v6",
	"etc/sysconfig/iptables",
	"etc/sysconfig/ip6tables",
}

// CollectRuleFileMtimes stats the known rule files under root plus every
// zone file in /etc/firewalld/zones, and reports path and mtime for each one
// that exists. os.Stat follows symlinks deliberately: the question is when
// the rule content changed, not when a link was rewired.
func CollectRuleFileMtimes(root string) *hostdoc.RuleFilesSection {
	sec := &hostdoc.RuleFilesSection{}

	paths := make([]string, 0, len(ruleFilePaths)+8)
	paths = append(paths, ruleFilePaths...)
	// The admin zone directory is dynamic: one file per zone.
	zoneDir := filepath.Join(root, "etc/firewalld/zones")
	sawPermErr := false
	// Listing this directory can be denied, and until 2026-08-18 that was
	// discarded. A denied listing then looked exactly like a host with no
	// zone files: none were added to the list, every stat below succeeded on
	// the static paths, and the section said collected. That is the section
	// claiming completeness it does not have, which is the same shape the
	// per-file stat below already guards against.
	if entries, err := os.ReadDir(zoneDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".xml") {
				paths = append(paths, filepath.Join("etc/firewalld/zones", e.Name()))
			}
		}
	} else if os.IsPermission(err) {
		sawPermErr = true
	}

	for _, rel := range paths {
		info, err := os.Stat(filepath.Join(root, rel))
		if err != nil {
			// Missing is the normal case for most of the list. A permission
			// error is remembered so a fully unreadable run is labelled
			// honestly rather than reported as "no rule files".
			if os.IsPermission(err) {
				sawPermErr = true
			}
			continue
		}
		if info.IsDir() {
			// A directory squatting on a rule-file path is not a rule file.
			continue
		}
		sec.Files = append(sec.Files, hostdoc.RuleFileStat{
			// The path is reported absolute, as the host knows it, and
			// sanitized: the static list is clean, but zone file names come
			// from the directory and an admin-created name is host text like
			// any other (RECORD.md 4.14).
			Path:      sanitizeName("/" + rel),
			MtimeUnix: info.ModTime().Unix(),
		})
	}

	sort.Slice(sec.Files, func(i, j int) bool { return sec.Files[i].Path < sec.Files[j].Path })

	// Any denied stat, not only a run where every one was denied. This
	// section answers "when did this change", and a file we were not allowed
	// to stat is missing from the list while looking exactly like a file that
	// is not installed. Saying collected there claims a completeness we do
	// not have, which is the shape RECORD.md 4.17 forbids: a healthy read
	// beside an unreadable one must never make the unreadable one look
	// measured and empty. There is no per-source map on this section to carry
	// the detail, so the section-level verdict has to.
	if sawPermErr {
		sec.Status = hostdoc.StatusPermissionDenied
		sec.Cause = hostdoc.CausePermission
		return sec
	}
	// Zero files found is a measured answer on a host with none of these
	// tools installed, not an error.
	sec.Status = hostdoc.StatusCollected
	return sec
}
