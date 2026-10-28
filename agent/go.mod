module github.com/whichports/whichports/agent

// The patch version is deliberate, not decorative. Every Go release fixes
// standard-library security bugs, and this line is what makes the toolchain
// refuse to build the agent with an older, unpatched one. Raise it whenever
// govulncheck reports a reachable stdlib finding: agent/SECURITY-REVIEW.md
// records why 1.26.6 was the floor chosen on 2026-08-15.
go 1.26.6

require (
	github.com/google/nftables v0.3.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.6.1 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
)
