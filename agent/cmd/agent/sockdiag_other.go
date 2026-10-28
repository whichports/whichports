//go:build !linux

package main

import (
	"github.com/whichports/whichports/agent/internal/collect"
)

// socketCgroups on a non-Linux build attempts nothing, so the sockets
// section carries no sock_diag or cgroup2 verdict at all: the honest value
// for "this build did not try" (PRODUCT.md 4b). sock_diag is a Linux netlink
// family and the agent only ships on Linux; this stub exists so development
// builds elsewhere stay possible.
func socketCgroups() collect.CgroupReader {
	return nil
}
