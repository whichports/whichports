package report

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// reportPath is the control plane ingest endpoint. The client owns the path,
// the config owns only the base URL, so the two cannot be combined into a
// surprising address.
const reportPath = "/api/v1/reports"

// sendTimeout bounds the whole request. A hung control plane must never
// wedge a timer run; the next tick is the retry.
const sendTimeout = 30 * time.Second

// drainLimit is how much of the response body is read, purely so the
// connection can be reused. The content is never looked at, and the cap means
// a hostile or broken control plane cannot make the agent read an unbounded
// stream.
const drainLimit = 4096

// Client delivers host documents. Outbound only (SI-1): it opens
// connections, never accepts them.
type Client struct {
	server     string
	credential string
	http       *http.Client
	// proberServer and proofKey are empty unless this host's control plane
	// uses our probers (prober.go).
	proberServer string
	proofKey     string
}

// NewClient builds the one HTTP client shape this agent ever uses. Two
// deliberate restrictions on top of the standard library defaults, the same
// two the client of an earlier project of the author's took, and for the
// same reasons:
//
//   - TLS 1.2 is the floor, stated here rather than inherited, so a future
//     default change can never silently lower it.
//   - Redirects are never followed. The control plane does not redirect, and
//     following one anyway would re-send the bearer credential to wherever
//     the response points. A 3xx surfaces as a plain non-2xx error.
func NewClient(cfg Config) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &Client{
		server:       cfg.Server,
		credential:   cfg.Credential,
		proberServer: cfg.ProberServer,
		proofKey:     cfg.ProofKey,
		http: &http.Client{
			Timeout:   sendTimeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Send delivers one marshalled host document, the same bytes stdout mode
// prints. The response is an acknowledgement: the status code decides
// success, the body is drained up to drainLimit and discarded unread (SI-2).
// Failure is returned, never retried here; the caller's next run is the
// retry, and the control plane's dead-man sweep is what notices a host that
// keeps failing.
func (c *Client) Send(ctx context.Context, document []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server+reportPath, bytes.NewReader(document))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "whichports-agent")
	req.Header.Set("Authorization", "Bearer "+c.credential)

	resp, err := c.http.Do(req)
	if err != nil {
		// err is a transport-level error (DNS, refused, TLS, timeout). It
		// goes to the local journal only, never onto any wire.
		return fmt.Errorf("deliver report: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		return nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("control plane refused the credential (HTTP %d): it may have been revoked, re-enroll from the dashboard", resp.StatusCode)
	default:
		return fmt.Errorf("control plane answered HTTP %d", resp.StatusCode)
	}
}

// presencePath is where the agent says "this is me, from this address" with
// no document. The control plane records nothing from the request but the
// address it arrived from, and proves it against the newest document it
// already holds, exactly as it does for a report (docs/PRODUCT.md 5).
const presencePath = "/api/v1/reports/presence"

// presenceTimeout is shorter than a report's: a family this host has no
// route on fails fast, and the timer run is not held for it.
const presenceTimeout = 10 * time.Second

// families are the two networks a presence request is sent over. A
// dual-stack host reaches the control plane over one of them for its report,
// which proves that one address; the other is proved by asking over it.
var families = []string{"tcp4", "tcp6"}

// ProveFamilies sends one empty presence request over each address family,
// after a report was delivered. Each is outbound only, carries the same
// credential, and its answer is discarded (SI-1, SI-2). A family this host
// cannot use fails to dial, which is the ordinary case on a single-stack
// host and is not an error anybody needs to read: the report already
// succeeded, and the address that family would have proved does not exist.
// So every failure is swallowed here, on purpose. Returned is how many of
// the two answered 2xx, for the journal line the caller writes.
func (c *Client) ProveFamilies(ctx context.Context) int {
	answered := 0
	for _, network := range families {
		if c.sendPresence(ctx, network) == nil {
			answered++
		}
	}
	return answered
}

// sendPresence is one presence request forced onto one network. The transport
// is a clone of the report's, with the dial pinned to `network`, so TLS floor
// and redirect refusal are the same and only the family differs.
func (c *Client) sendPresence(ctx context.Context, network string) error {
	transport, ok := c.http.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("transport is not an *http.Transport")
	}
	pinned := transport.Clone()
	dialer := &net.Dialer{Timeout: presenceTimeout}
	pinned.DialContext = func(ctx context.Context, _ string, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}
	client := &http.Client{Timeout: presenceTimeout, Transport: pinned,
		CheckRedirect: c.http.CheckRedirect}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server+presencePath, http.NoBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "whichports-agent")
	req.Header.Set("Authorization", "Bearer "+c.credential)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("control plane answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// A self-hosted whichports uses our probers, and our probers probe only an
// address that was proved to us (SI-6). This host reports to its own control
// plane, which we never see, so it proves its addresses to our prober API
// itself: one request over each address family, carrying the public
// addresses on its interfaces and nothing else. The API proves the address a
// request arrived from, and only when the request says the host holds it,
// the same two halves as the presence request above (docs/PRODUCT.md 5,
// docs/RECORD.md 4.185).
//
// Outbound only, and the answer is drained and never read (SI-1, SI-2). A
// family this host has no route on fails to dial and is swallowed, exactly as
// ProveFamilies does.

// proberPresencePath is where our prober API takes an agent's presence.
const proberPresencePath = "/api/v1/prober/presence"

// MaxClaimedAddresses bounds the list. The API reads more than 64 as not a
// claim at all, so a host with more public addresses than that sends 64.
const MaxClaimedAddresses = 64

// ProveToProber sends one presence request over each address family to the
// prober API, when this host is configured for one. Returned is how many of
// the two answered 2xx, for the journal. Every failure is swallowed: the
// report to the host's own control plane is what can fail a run, never this.
//
// The addresses are typed, so nothing but an address can reach the body.
func (c *Client) ProveToProber(ctx context.Context, addresses []netip.Addr) int {
	if c.proberServer == "" || len(addresses) == 0 {
		return 0
	}
	body := presenceBody(addresses)
	answered := 0
	for _, network := range families {
		if c.sendProberPresence(ctx, network, body) == nil {
			answered++
		}
	}
	return answered
}

// presenceBody is {"interface_addresses": [...]}, written by hand because
// this package imports no JSON library (the safety scan's ban on decoders
// here). An address's text is digits, hex, dots and colons, and it is quoted
// anyway.
func presenceBody(addresses []netip.Addr) []byte {
	if len(addresses) > MaxClaimedAddresses {
		addresses = addresses[:MaxClaimedAddresses]
	}
	quoted := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		quoted = append(quoted, strconv.Quote(addr.String()))
	}
	return []byte(`{"interface_addresses":[` + strings.Join(quoted, ",") + `]}`)
}

// sendProberPresence is one request pinned to one network, on a clone of the
// report's transport, so the TLS floor and the redirect refusal are the same.
func (c *Client) sendProberPresence(ctx context.Context, network string, body []byte) error {
	transport, ok := c.http.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("transport is not an *http.Transport")
	}
	pinned := transport.Clone()
	dialer := &net.Dialer{Timeout: presenceTimeout}
	pinned.DialContext = func(ctx context.Context, _ string, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}
	client := &http.Client{Timeout: presenceTimeout, Transport: pinned,
		CheckRedirect: c.http.CheckRedirect}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.proberServer+proberPresencePath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "whichports-agent")
	req.Header.Set("Authorization", "Bearer "+c.proofKey)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("prober API answered HTTP %d", resp.StatusCode)
	}
	return nil
}
