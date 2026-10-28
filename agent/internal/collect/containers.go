// This file is the container collector: which containers are running and
// which ports they publish, read with one GET over each runtime's local unix
// socket. Reading a unix socket is not an exec (docs/PRODUCT.md 4e), the
// request is outbound, and the response is recorded, never acted on (SI-2).
// Docker and Podman are collected separately because they are not
// interchangeable (PRODUCT.md 4, 4d): Docker DNATs through the kernel's own
// nat chains, rootful Podman's netavark uses its own nftables table.
package collect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// containerRuntimes are the sockets this collector checks, relative to the
// filesystem root. Both are the runtimes' standard rootful socket locations;
// the podman one was confirmed live on AlmaLinux 10.2 (2026-08-13). Rootless
// runtimes publish through a userspace proxy whose listening socket the
// sockets collector already reports with its owning process (PRODUCT.md 4).
var containerRuntimes = []struct {
	name   string // the Sources key: "docker" or "podman"
	socket string
}{
	{"docker", "var/run/docker.sock"},
	{"podman", "run/podman/podman.sock"},
}

// containerAPITimeout bounds the whole conversation with a runtime. A hung
// daemon must delay the document, not hang the agent.
const containerAPITimeout = 5 * time.Second

// containerResponseLimit caps how much of a response is read. A list of
// running containers is kilobytes; anything past this is not that.
const containerResponseLimit = 8 << 20

// CollectContainers queries each runtime socket present under root. A missing
// socket is not_present, the normal state on most hosts. Podman serves the
// Docker-compatible list endpoint on its own socket, so one response shape
// covers both (podman-system-service(1)).
func CollectContainers(root string) *hostdoc.ContainersSection {
	sec := &hostdoc.ContainersSection{Sources: map[string]hostdoc.Section{}}

	for _, rt := range containerRuntimes {
		socketPath := filepath.Join(root, rt.socket)
		if _, err := os.Stat(socketPath); err != nil {
			sec.Sources[rt.name] = fileVerdict(err)
			continue
		}
		client := &http.Client{
			Timeout: containerAPITimeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		}
		containers, verdict := queryContainers(client)
		sec.Sources[rt.name] = verdict
		switch rt.name {
		case "docker":
			sec.Docker = containers
		case "podman":
			sec.Podman = containers
		}
	}

	sec.Section = aggregateSources(sec.Sources)
	return sec
}

// containerRequestVerdict classifies a failed conversation with a runtime.
// The socket existed, so this is not absence. Three answers, and telling them
// apart matters: "the daemon is broken" and "you are not allowed to ask it"
// send an operator to different places, and this is a tool whose whole job is
// not guessing.
//
// The permission case is the one that used to be missing. connect(2) on a
// root-owned or docker-group-owned socket returns EACCES to anyone else, and
// reporting that as a socket error said the daemon was at fault when the
// agent simply was not allowed to look. Every other collector in this package
// draws the distinction; this one now does too.
func containerRequestVerdict(err error) hostdoc.Section {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseTimeout}
	}
	if errors.Is(err, os.ErrPermission) {
		return hostdoc.Section{Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission}
	}
	return hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseSocketError}
}

// apiContainer is the slice of the runtimes' container-list response this
// collector reads. Unknown fields are ignored.
type apiContainer struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
	Ports []struct {
		IP          string `json:"IP"`
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

// queryContainers performs the one GET and maps the response. The URL host is
// a placeholder: the transport dials the unix socket regardless. Only running
// containers are listed, which is the endpoint's default and the set that can
// hold a port open.
func queryContainers(client *http.Client) ([]hostdoc.Container, hostdoc.Section) {
	resp, err := client.Get("http://unix/containers/json")
	if err != nil {
		return nil, containerRequestVerdict(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	}

	var raw []apiContainer
	if err := json.NewDecoder(io.LimitReader(resp.Body, containerResponseLimit)).Decode(&raw); err != nil {
		return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
	}

	out := make([]hostdoc.Container, 0, len(raw))
	for _, c := range raw {
		// The document's marshaller fails closed on an empty id or an
		// out-of-range port, and it must: but a malformed daemon response has
		// to become this section's parse failure, never a failure of the
		// whole document. Guard here so the fail-closed layer never fires.
		if sanitizeName(c.ID) == "" {
			return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
		}
		name := ""
		if len(c.Names) > 0 {
			// Docker reports names with a leading slash.
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		oc := hostdoc.Container{
			ID:    sanitizeName(c.ID),
			Name:  sanitizeName(name),
			Image: sanitizeName(c.Image),
		}
		for _, p := range c.Ports {
			if p.PublicPort == 0 {
				// Exposed but not published: nothing reaches the host's
				// interfaces through it, so it is not a publication.
				continue
			}
			if p.PublicPort < 0 || p.PublicPort > 65535 || p.PrivatePort < 0 || p.PrivatePort > 65535 {
				return nil, hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
			}
			oc.Ports = append(oc.Ports, hostdoc.PublishedPort{
				HostIP:        sanitizeName(p.IP),
				HostPort:      p.PublicPort,
				ContainerPort: p.PrivatePort,
				Protocol:      sanitizeName(p.Type),
			})
		}
		sort.Slice(oc.Ports, func(i, j int) bool {
			a, b := oc.Ports[i], oc.Ports[j]
			if a.HostPort != b.HostPort {
				return a.HostPort < b.HostPort
			}
			if a.ContainerPort != b.ContainerPort {
				return a.ContainerPort < b.ContainerPort
			}
			if a.Protocol != b.Protocol {
				return a.Protocol < b.Protocol
			}
			return a.HostIP < b.HostIP
		})
		out = append(out, oc)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, hostdoc.Section{Status: hostdoc.StatusCollected}
}
