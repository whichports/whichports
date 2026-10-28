// Package report is the agent's one outbound channel: it delivers the host
// document to the control plane in a single HTTPS POST. The whole package is
// written around one property, stated here so a reviewer can hold the code
// to it:
//
//	The agent never parses a byte of any HTTP response. The response to a
//	report is an acknowledgement, read as a status code and nothing else
//	(SI-2). Even enrollment involves no network: the dashboard generates
//	the credential and `whichports-agent enroll` only writes it to a local
//	file. There is no response-parsing code to audit because there is none.
//
// The safety tests confine net/http to this package plus the container
// collector's local unix-socket read, so a new network path anywhere else in
// the agent fails the suite. The design is recorded in docs/PRODUCT.md 4f.
package report

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// DefaultConfigPath is where enrollment writes the configuration and where
// the reporting modes read it. stdout mode never touches it.
const DefaultConfigPath = "/etc/whichports/agent.conf"

// ErrNotEnrolled means the configuration file does not exist. The timer mode
// treats this as "local-only host, nothing to send", which keeps the packaged
// default of nothing-leaves-the-machine. The oneshot mode treats it as an
// error, because someone asked for a report to be sent.
var ErrNotEnrolled = errors.New("not enrolled: no " + DefaultConfigPath + " (run `whichports-agent enroll`, credential from the dashboard)")

// Config is what `whichports-agent enroll` writes and the reporting modes
// read. Key-value lines, sysadmin-plain.
type Config struct {
	// Server is the control plane base URL, https unless AllowHTTP.
	Server string
	// Credential is this host's bearer credential. It authorises exactly one
	// thing: posting this host's own report.
	Credential string
	// AllowHTTP permits a plain-http server URL. Lab testing only, and it
	// exists so the choice is written in the config file rather than made
	// silently by the code.
	AllowHTTP bool
	// ProberServer is our prober API, for a self-hosted control plane that
	// uses our probers. Empty on a host that reports to us directly. When
	// set, the agent tells it which public addresses this host holds, so
	// those addresses may be probed (prober.go). Both of these or neither.
	ProberServer string
	// ProofKey authorises exactly one thing at ProberServer: saying which
	// addresses this host holds, from those addresses. It cannot send a probe
	// or read a result.
	ProofKey string
}

// Load reads and validates the configuration. A missing file is
// ErrNotEnrolled. A file that anyone outside root and the agent's own group
// can touch is refused outright, the same posture the OpenSSH client takes
// with a private key file other users can read: a credential the whole box
// can read is a misconfiguration, not something to work around.
//
// Group read is allowed and group write is not. The packaged agent runs as
// the whichports-agent user and reads the root-owned file through its group
// (docs/RECORD.md 4.72), so the intended mode is 0640 root:whichports-agent,
// and a root-only 0600 file still loads for anyone running the agent as root
// by hand.
func Load(path string) (Config, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, ErrNotEnrolled
	}
	if errors.Is(err, fs.ErrPermission) {
		// stat needs nothing from the file itself, only search on the
		// directories above it, so a refusal here is about the directory. The
		// file looks right in ls, which is where anyone would look first
		// (docs/RECORD.md 4.201).
		dir := filepath.Dir(path)
		return Config{}, fmt.Errorf("read config: %w: the agent's user needs search permission on %s, chmod go+x %s", err, dir, dir)
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if info.Mode().Perm()&0o027 != 0 {
		return Config{}, fmt.Errorf("%s is group-writable or accessible to others (mode %#o), refusing to use the credential: chown root:whichports-agent and chmod 640 it", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return parse(string(raw))
}

// parse is strict on purpose: an unknown key is an error, not a warning,
// because a typo like `sever` silently ignored would mean a host that never
// reports and never says why.
func parse(raw string) (Config, error) {
	var cfg Config
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, " ")
		value = strings.TrimSpace(value)
		if !found || value == "" {
			return Config{}, fmt.Errorf("config line %d: want `key value`, got %q", i+1, line)
		}
		switch key {
		case "server":
			cfg.Server = value
		case "credential":
			cfg.Credential = value
		case "prober_server":
			cfg.ProberServer = value
		case "prober_proof_key":
			cfg.ProofKey = value
		case "allow_http":
			switch value {
			case "yes":
				cfg.AllowHTTP = true
			case "no":
				cfg.AllowHTTP = false
			default:
				return Config{}, fmt.Errorf("config line %d: allow_http wants yes or no, got %q", i+1, value)
			}
		default:
			return Config{}, fmt.Errorf("config line %d: unknown key %q", i+1, key)
		}
	}
	if cfg.Server == "" {
		return Config{}, errors.New("config: missing server")
	}
	if cfg.Credential == "" {
		return Config{}, errors.New("config: missing credential")
	}
	server, err := ValidateServer(cfg.Server, cfg.AllowHTTP)
	if err != nil {
		return Config{}, err
	}
	cfg.Server = server
	if err := ValidateCredential(cfg.Credential); err != nil {
		return Config{}, err
	}
	prober, err := ValidateProber(cfg.ProberServer, cfg.ProofKey, cfg.AllowHTTP)
	if err != nil {
		return Config{}, err
	}
	cfg.ProberServer = prober
	return cfg, nil
}

// ValidateProber checks the prober API's two settings together: both empty,
// which is a host that reports to us directly, or a base URL and a proof key.
// One without the other is refused, because a host that half set it up would
// never prove its addresses and nothing would say why. Shared by enrollment
// and config load, like ValidateServer.
func ValidateProber(server, proofKey string, allowHTTP bool) (string, error) {
	if server == "" && proofKey == "" {
		return "", nil
	}
	if server == "" || proofKey == "" {
		return "", errors.New("prober_server and prober_proof_key go together, and only one is set")
	}
	normalised, err := ValidateServer(server, allowHTTP)
	if err != nil {
		return "", fmt.Errorf("prober server: %w", err)
	}
	if err := validateKey(proofKey, "whpp_", "proof key", "copy it exactly as the install command gives it"); err != nil {
		return "", err
	}
	return normalised, nil
}

// ValidateServer checks and normalises the control plane base URL. It is
// shared by enrollment and config load so the two can never drift apart.
// The path is fixed by the client, so a URL carrying its own path, query,
// fragment or userinfo is refused rather than combined into something
// surprising.
func ValidateServer(raw string, allowHTTP bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("server URL %q: %v", raw, err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return "", fmt.Errorf("server URL %q is plain http: use https, or state --allow-http explicitly for lab testing", raw)
		}
	default:
		return "", fmt.Errorf("server URL %q: want https://host, got scheme %q", raw, u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("server URL %q has no host", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("server URL %q carries credentials in the URL, the credential belongs in its own field", raw)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("server URL %q: want the bare base URL, no path or query", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

// ValidateCredential checks the credential's shape without ever logging its
// value: error messages describe the problem, never echo the secret.
func ValidateCredential(s string) error {
	return validateKey(s, "whp_", "credential", "copy it exactly as the dashboard shows it")
}

// validateKey is the one shape check for every secret the config holds: its
// prefix, a body long enough to be random, a length cap, and a charset. The
// message names what is wrong and where to copy it from, and never echoes
// the value.
func validateKey(s, prefix, what, hint string) error {
	if !strings.HasPrefix(s, prefix) {
		return fmt.Errorf("%s does not start with %s, %s", what, prefix, hint)
	}
	body := strings.TrimPrefix(s, prefix)
	if len(body) < 32 {
		return fmt.Errorf("%s is too short, %s", what, hint)
	}
	if len(s) > 128 {
		return fmt.Errorf("%s is too long, %s", what, hint)
	}
	for _, r := range body {
		valid := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '-' || r == '_'
		if !valid {
			return fmt.Errorf("%s contains a character that cannot be part of one, %s", what, hint)
		}
	}
	return nil
}
