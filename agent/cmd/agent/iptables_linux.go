//go:build linux

package main

import (
	"github.com/whichports/whichports/agent/internal/collect"
	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// The legacy x_tables reads use Linux-only syscalls, so they follow the same
// per-platform pattern as the nftables collector.
func collectIptables() *hostdoc.IptablesSection  { return collect.CollectIptablesLive() }
func collectIp6tables() *hostdoc.IptablesSection { return collect.CollectIp6tablesLive() }
