//go:build !linux

package main

import (
	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// Non-Linux development builds report not_collected honestly, the same
// posture as the nftables stub.
func collectIptables() *hostdoc.IptablesSection {
	return &hostdoc.IptablesSection{Section: hostdoc.Section{Status: hostdoc.StatusNotCollected}}
}

func collectIp6tables() *hostdoc.IptablesSection {
	return &hostdoc.IptablesSection{Section: hostdoc.Section{Status: hostdoc.StatusNotCollected}}
}
