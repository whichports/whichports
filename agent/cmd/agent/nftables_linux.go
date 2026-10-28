//go:build linux

package main

import (
	"github.com/whichports/whichports/agent/internal/collect"
	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// collectNftables reads the live ruleset over netlink. Linux only, which is
// the only platform the agent ships on.
func collectNftables() *hostdoc.NftablesSection {
	return collect.CollectNftablesLive()
}
