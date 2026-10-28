//go:build linux

package main

import (
	"github.com/whichports/whichports/agent/internal/collect"
)

// socketCgroups reads which unit owns each listening socket from the live
// kernel. Linux only, which is the only platform the agent ships on.
func socketCgroups() collect.CgroupReader {
	return collect.SocketCgroupsLive
}
