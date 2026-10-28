package report

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// agentGroupName is the system group the packaged unit runs under. Enrollment
// grants it read on the config so the non-root agent can load the credential.
const agentGroupName = "whichports-agent"

// WriteConfig writes the enrollment result to disk, atomically. This is the
// whole of enrollment: no network, no exchange, no response to parse. The
// dashboard generated the credential, the operator carried it here, and this
// function writes it down.
//
// Ownership follows how the agent runs (docs/RECORD.md 4.72). On a packaged
// host, where the whichports-agent group exists and enroll runs as root, the
// file ends up root:whichports-agent 0640 so the unit's non-root user can
// read it. Anywhere else it stays 0600 for the writing user, which is the
// right shape for an agent run by hand.
func WriteConfig(path string, cfg Config) error {
	gid, packaged := agentGroupID()
	return writeConfig(path, cfg, gid, packaged)
}

// writeConfig is WriteConfig with the packaged-host decision passed in. The
// packaged branch hands the file to the whichports-agent group, which only
// root can do, so the tests run it with a group the test process belongs to
// instead, and exercise the same code a real enrolment runs.
func writeConfig(path string, cfg Config, gid int, packaged bool) error {
	server, err := ValidateServer(cfg.Server, cfg.AllowHTTP)
	if err != nil {
		return err
	}
	if err := ValidateCredential(cfg.Credential); err != nil {
		return err
	}
	prober, err := ValidateProber(cfg.ProberServer, cfg.ProofKey, cfg.AllowHTTP)
	if err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("# whichports agent configuration, written by `whichports-agent enroll`.\n")
	b.WriteString("# The credential authorises one thing: posting this host's own report to\n")
	b.WriteString("# the server below. Revoke or replace it from the dashboard at any time.\n")
	fmt.Fprintf(&b, "server %s\n", server)
	fmt.Fprintf(&b, "credential %s\n", cfg.Credential)
	if cfg.AllowHTTP {
		b.WriteString("# allow_http permits a plain-http server URL, so the credential and the\n")
		b.WriteString("# document travel unencrypted. Lab testing only, never across a network\n")
		b.WriteString("# you do not fully control.\n")
		b.WriteString("allow_http yes\n")
	}
	if prober != "" {
		b.WriteString("# Your control plane uses whichports' probers. After each collection the\n")
		b.WriteString("# agent tells the prober server below which public addresses this host\n")
		b.WriteString("# holds, so they may be probed from outside. That list is all it sends\n")
		b.WriteString("# there, and the proof key authorises nothing else.\n")
		fmt.Fprintf(&b, "prober_server %s\n", prober)
		fmt.Fprintf(&b, "prober_proof_key %s\n", cfg.ProofKey)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if packaged {
		if err := openDirectoryToAgent(dir); err != nil {
			return err
		}
	}
	// Temp file in the same directory so the rename is atomic, created 0600
	// before the credential is written into it, so there is no instant where
	// the secret sits in a file anyone else can read. The group grant below
	// happens on the temp file too, before the rename, for the same reason.
	tmp, err := os.CreateTemp(dir, ".agent.conf.*")
	if err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if packaged {
		// -1 keeps the owner. A failed grant is a real error rather than a
		// fallback to 0600, because a packaged host with an unreadable config
		// would fail on every timer tick with nothing pointing at the cause.
		if err := tmp.Chown(-1, gid); err != nil {
			tmp.Close()
			return fmt.Errorf("granting the %s group read on the config: %w", agentGroupName, err)
		}
		if err := tmp.Chmod(0o640); err != nil {
			tmp.Close()
			return fmt.Errorf("write config: %w", err)
		}
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// openDirectoryToAgent makes sure the agent's user can enter the directory
// that holds its config.
//
// A process needs search permission on a directory before it can even stat a
// file inside it (path_resolution(7)). MkdirAll's 0755 is trimmed by the
// umask of whoever ran enroll, and sudo keeps the operator's umask when it is
// stricter than 022 (sudoers(5)). So on a host whose admins set umask 027 or
// 077 the directory came out 0750 or 0700 root:root, and the agent failed on
// every run with "stat /etc/whichports/agent.conf: permission denied" while
// the file itself looked right (docs/RECORD.md 4.201). Setting the bits
// explicitly takes the umask out of it, and doing it on every enrol also
// repairs a directory an earlier enrol left shut.
//
// Search for group and for others, because the agent is judged by the group
// bits when it is in the directory's group and by the other bits when it is
// not. Read is not added: the agent opens its config by name and never lists
// the directory. Nothing is taken away either. On the control plane's own box
// this directory also holds the control plane's settings, so any mode someone
// chose there stays, and only these two bits are ours to add.
//
// A symlink is refused rather than followed, for the reason postinstall.sh
// gives for its own two paths: chmod follows a link, so a link planted here
// would have root change whatever it points at, and the credential would be
// written through it.
func openDirectoryToAgent(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("opening %s to the agent: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink, refusing to write the credential through it: remove the link and enroll again", dir)
	}
	// Keep setuid, setgid and sticky as they are, since a chmod given only
	// the permission bits would clear them.
	kept := info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	want := kept | 0o011
	if want == kept {
		return nil
	}
	if err := os.Chmod(dir, want); err != nil {
		return fmt.Errorf("opening %s to the agent: %w", dir, err)
	}
	return nil
}

// agentGroupID reports the whichports-agent group's gid when the group exists
// and this process is root, which is the packaged-install case. Any other
// case, including a hand-run enroll by an unprivileged user in a lab, gets
// the root-only 0600 file instead of a chown that cannot succeed.
func agentGroupID() (int, bool) {
	if os.Geteuid() != 0 {
		return 0, false
	}
	g, err := user.LookupGroup(agentGroupName)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, false
	}
	return gid, true
}
