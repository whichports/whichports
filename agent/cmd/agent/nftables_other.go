//go:build !linux

package main

import (
	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// collectNftables on a non-Linux build reports not_collected, the honest
// value for "this build did not attempt it" (PRODUCT.md 4b). The nftables
// netlink library only compiles on Linux, and the agent only ships on Linux;
// this stub exists so development builds elsewhere stay possible.
func collectNftables() *hostdoc.NftablesSection {
	return &hostdoc.NftablesSection{Section: hostdoc.Section{Status: hostdoc.StatusNotCollected}}
}
