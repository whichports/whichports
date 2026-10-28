package report

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// A well-formed credential for tests: whp_ plus 64 hex characters, the shape
// the dashboard generates.
const testCredential = "whp_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// --- configuration parsing ---

func TestParseValidConfig(t *testing.T) {
	cfg, err := parse("# a comment\n\nserver https://app.example.test\ncredential " + testCredential + "\n")
	if err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	if cfg.Server != "https://app.example.test" {
		t.Errorf("server = %q", cfg.Server)
	}
	if cfg.Credential != testCredential {
		t.Errorf("credential did not round-trip")
	}
	if cfg.AllowHTTP {
		t.Errorf("allow_http must default to off")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key (typo protection)": "sever https://x.test\ncredential " + testCredential,
		"missing credential":            "server https://x.test",
		"missing server":                "credential " + testCredential,
		"key without value":             "server\ncredential " + testCredential,
		"bad allow_http value":          "server https://x.test\ncredential " + testCredential + "\nallow_http maybe",
		"http without allow_http":       "server http://x.test\ncredential " + testCredential,
		"unknown scheme":                "server ftp://x.test\ncredential " + testCredential,
		"URL with path":                 "server https://x.test/api\ncredential " + testCredential,
		"URL with query":                "server https://x.test?a=b\ncredential " + testCredential,
		"URL with userinfo":             "server https://user:pw@x.test\ncredential " + testCredential,
		"credential wrong prefix":       "server https://x.test\ncredential abc_0123456789abcdef0123456789abcdef",
		"credential too short":          "server https://x.test\ncredential whp_abc",
		"credential bad character":      "server https://x.test\ncredential whp_0123456789abcdef0123456789abcdef!!",
		"credential too long":           "server https://x.test\ncredential whp_" + strings.Repeat("a", 200),
	}
	for name, raw := range cases {
		if _, err := parse(raw); err == nil {
			t.Errorf("%s: parse accepted %q", name, raw)
		}
	}
}

func TestParseAllowsHTTPWhenStated(t *testing.T) {
	cfg, err := parse("server http://127.0.0.1:8080\ncredential " + testCredential + "\nallow_http yes\n")
	if err != nil {
		t.Fatalf("explicit allow_http refused: %v", err)
	}
	if cfg.Server != "http://127.0.0.1:8080" {
		t.Errorf("server = %q", cfg.Server)
	}
}

func TestValidateServerNormalisesTrailingSlash(t *testing.T) {
	got, err := ValidateServer("https://x.test/", false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://x.test" {
		t.Errorf("want bare base URL, got %q", got)
	}
}

// Error messages must describe a credential problem without echoing the
// secret itself, or the secret ends up in journals and terminals.
func TestCredentialErrorsNeverEchoTheSecret(t *testing.T) {
	secret := "whp_deadbeef!" // invalid character, and recognisable
	err := ValidateCredential(secret)
	if err == nil {
		t.Fatal("invalid credential accepted")
	}
	if strings.Contains(err.Error(), "deadbeef") {
		t.Errorf("error message echoes the credential: %q", err.Error())
	}
}

// --- Load ---

func TestLoadMissingFileIsNotEnrolled(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.conf"))
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("want ErrNotEnrolled, got %v", err)
	}
}

// Group read is the one grant Load allows beyond the owner, because the
// packaged agent runs as the whichports-agent user and reads the root-owned
// config through its group (docs/RECORD.md 4.72). Everything wider stays
// refused: a group that can write the file can swap the server the credential
// is sent to, and others get nothing at all.
func TestLoadPermissionBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	content := "server https://x.test\ncredential " + testCredential + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode os.FileMode
		ok   bool
		why  string
	}{
		{0o600, true, "root-only is the hand-run shape"},
		{0o640, true, "group read is how the packaged non-root agent loads it"},
		{0o644, false, "world-readable leaks the credential"},
		{0o660, false, "group write lets the group redirect the report"},
		{0o604, false, "other-readable leaks the credential"},
		{0o601, false, "any access for others is too much"},
	} {
		if err := os.Chmod(path, tc.mode); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if tc.ok && err != nil {
			t.Errorf("mode %#o refused and it must load (%s): %v", tc.mode, tc.why, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("mode %#o loaded and it must be refused (%s)", tc.mode, tc.why)
		}
	}
}

// --- enrollment ---

func TestWriteConfigRoundTripsThroughLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	in := Config{Server: "https://app.example.test", Credential: testCredential}
	if err := WriteConfig(path, in); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Two legitimate shapes, decided by the machine the test runs on. On a
	// packaged host, root enrolling grants the agent group read (0640). Every
	// other environment, and that is every CI and dev machine, has no
	// whichports-agent group, so the file stays owner-only. The packaged
	// shape is asserted against a real install by ops/cleanbox.
	want := os.FileMode(0o600)
	if _, ok := agentGroupID(); ok {
		want = 0o640
	}
	if info.Mode().Perm() != want {
		t.Errorf("config written %#o, want %#o", info.Mode().Perm(), want)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Errorf("round trip changed the config: wrote %+v, read %+v", in, out)
	}
}

func TestWriteConfigReplacesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	first := Config{Server: "https://old.example.test", Credential: testCredential}
	if err := WriteConfig(path, first); err != nil {
		t.Fatal(err)
	}
	second := Config{Server: "https://new.example.test", Credential: testCredential}
	if err := WriteConfig(path, second); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Server != "https://new.example.test" {
		t.Errorf("re-enrollment did not replace the config, server = %q", out.Server)
	}
}

func TestWriteConfigPersistsAllowHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	in := Config{Server: "http://127.0.0.1:9", Credential: testCredential, AllowHTTP: true}
	if err := WriteConfig(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !out.AllowHTTP {
		t.Error("allow_http was not persisted")
	}
}

func TestWriteConfigRefusesInvalidInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	if err := WriteConfig(path, Config{Server: "http://x.test", Credential: testCredential}); err == nil {
		t.Error("http server accepted without AllowHTTP")
	}
	if err := WriteConfig(path, Config{Server: "https://x.test", Credential: "whp_short"}); err == nil {
		t.Error("invalid credential accepted")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("a refused enrollment must not leave a config file behind")
	}
}

// --- the client ---

// testClient builds a client aimed at a test server over plain http, which is
// exactly what allow_http exists for.
func testClient(serverURL string) *Client {
	return NewClient(Config{Server: serverURL, Credential: testCredential, AllowHTTP: true})
}

func TestSendDeliversDocumentVerbatim(t *testing.T) {
	document := []byte(`{"schema_version":1,"hostname":"box"}`)
	var gotBody []byte
	var gotAuth, gotType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotType = r.Header.Get("Content-Type")
		var buf bytes.Buffer
		buf.ReadFrom(r.Body)
		gotBody = buf.Bytes()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := testClient(srv.URL).Send(context.Background(), document); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	if !bytes.Equal(gotBody, document) {
		t.Errorf("document was altered in transit: sent %q, server saw %q", document, gotBody)
	}
	if gotAuth != "Bearer "+testCredential {
		t.Errorf("authorization header = %q", gotAuth)
	}
	if gotType != "application/json" {
		t.Errorf("content type = %q", gotType)
	}
}

func TestSendErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := testClient(srv.URL).Send(context.Background(), []byte("{}")); err == nil {
		t.Fatal("a 500 must surface as an error")
	}
}

func TestSendNamesARevokedCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	err := testClient(srv.URL).Send(context.Background(), []byte("{}"))
	if err == nil {
		t.Fatal("a 401 must surface as an error")
	}
	if !strings.Contains(err.Error(), "credential") {
		t.Errorf("a 401 should tell the operator it is about the credential, said %q", err.Error())
	}
}

// The credential must never be re-sent to wherever a response points. A
// redirect is answered by giving up, and the redirect target is never
// contacted.
func TestSendNeverFollowsRedirects(t *testing.T) {
	targetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit = true
	}))
	defer target.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusMovedPermanently)
	}))
	defer redirecting.Close()

	err := testClient(redirecting.URL).Send(context.Background(), []byte("{}"))
	if err == nil {
		t.Fatal("a redirect must surface as an error, not be followed")
	}
	if targetHit {
		t.Fatal("the redirect target was contacted: the credential travelled to a third party")
	}
}

// A hostile control plane answering 200 with garbage must change nothing:
// the agent reads the status code and discards the body. Success with a
// megabyte of noise is still just success.
func TestSendIgnoresResponseBodyEntirely(t *testing.T) {
	noise := bytes.Repeat([]byte(`{"cmd":"rm -rf /"} `), 65536) // ~1.2MB of would-be commands
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(noise)
	}))
	defer srv.Close()
	if err := testClient(srv.URL).Send(context.Background(), []byte("{}")); err != nil {
		t.Fatalf("a 2xx with a hostile body is still an acknowledgement: %v", err)
	}
}

// Certificate verification stays on: a TLS server the system roots do not
// vouch for is refused. httptest's TLS server signs with its own throwaway
// CA, which is exactly the untrusted case.
func TestSendRefusesUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	client := NewClient(Config{Server: srv.URL, Credential: testCredential})
	if err := client.Send(context.Background(), []byte("{}")); err == nil {
		t.Fatal("an untrusted certificate must fail the send")
	}
}

// White-box: the constructed client carries the two restrictions the design
// promises, so a refactor that drops either breaks here rather than silently.
func TestClientConstruction(t *testing.T) {
	c := NewClient(Config{Server: "https://x.test", Credential: testCredential})
	transport, ok := c.http.Transport.(*http.Transport)
	if !ok {
		t.Fatal("client transport is not the expected *http.Transport")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Error("TLS 1.2 floor is not set")
	}
	if c.http.CheckRedirect == nil {
		t.Error("redirect policy is not set, the default client would follow redirects")
	}
	if err := c.http.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Error("redirect policy must be ErrUseLastResponse")
	}
	if c.http.Timeout == 0 {
		t.Error("the client has no timeout, a hung control plane would wedge the run")
	}
}

// The presence request: one per address family after a report, empty body,
// the same credential, forced onto the family it names. The test server
// listens on 127.0.0.1, so tcp4 reaches it and tcp6 cannot dial it at all,
// which is exactly a single-stack host's situation and must not be an error.
func TestProveFamiliesAsksOverEachFamilyAndSwallowsTheOneThatCannotDial(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	var bodies []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		buf.ReadFrom(r.Body)
		mu.Lock()
		seen = append(seen, r.URL.Path+" "+r.Header.Get("Authorization"))
		bodies = append(bodies, buf.Len())
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	answered := testClient(srv.URL).ProveFamilies(context.Background())
	if answered != 1 {
		t.Fatalf("answered = %d, want 1: tcp4 reaches a 127.0.0.1 server and tcp6 cannot", answered)
	}
	if len(seen) != 1 || seen[0] != "/api/v1/reports/presence Bearer "+testCredential {
		t.Errorf("requests seen = %q", seen)
	}
	if bodies[0] != 0 {
		t.Errorf("a presence request carries no document, body was %d bytes", bodies[0])
	}
}

func TestProveFamiliesCountsOnlyA2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	if got := testClient(srv.URL).ProveFamilies(context.Background()); got != 0 {
		t.Errorf("answered = %d, want 0 on a refusal", got)
	}
}
