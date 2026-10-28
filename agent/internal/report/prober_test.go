package report

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The presence request to our prober API, for a host whose control plane
// uses our probers. What these hold: the two settings go together, the
// request carries the addresses and nothing else, the answer is never read,
// and a host that is not configured for it sends nothing at all.

const testProofKey = "whpp_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func proberConfig(server string) string {
	return "server https://cp.example.test\ncredential " + testCredential + "\n" + server
}

func TestProberSettingsGoTogether(t *testing.T) {
	cases := map[string]string{
		"server without a key": "prober_server https://app.whichports.com\n",
		"key without a server": "prober_proof_key " + testProofKey + "\n",
		"plain http":           "prober_server http://app.whichports.com\nprober_proof_key " + testProofKey + "\n",
		"a host credential":    "prober_server https://app.whichports.com\nprober_proof_key " + testCredential + "\n",
		"a short key":          "prober_server https://app.whichports.com\nprober_proof_key whpp_abc\n",
		"a path on the server": "prober_server https://app.whichports.com/api\nprober_proof_key " + testProofKey + "\n",
	}
	for name, lines := range cases {
		_, err := parse(proberConfig(lines))
		if err == nil {
			t.Errorf("%s: parsed, want a refusal", name)
			continue
		}
		if strings.Contains(err.Error(), testProofKey) || strings.Contains(err.Error(), testCredential) {
			t.Errorf("%s: the error echoes a secret: %v", name, err)
		}
	}
}

func TestProberSettingsParseWhenBothAreThere(t *testing.T) {
	cfg, err := parse(proberConfig("prober_server https://app.whichports.com/\nprober_proof_key " + testProofKey + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProberServer != "https://app.whichports.com" || cfg.ProofKey != testProofKey {
		t.Errorf("got %q and %q", cfg.ProberServer, cfg.ProofKey)
	}
}

func TestAConfigWithoutProberSettingsIsUnchanged(t *testing.T) {
	cfg, err := parse(proberConfig(""))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProberServer != "" || cfg.ProofKey != "" {
		t.Errorf("prober settings appeared from nowhere: %+v", cfg)
	}
}

func TestWriteConfigRoundTripsTheProberSettingsAndSaysWhatTheyDo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	err := WriteConfig(path, Config{Server: "https://cp.example.test", Credential: testCredential,
		ProberServer: "https://app.whichports.com", ProofKey: testProofKey})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProberServer != "https://app.whichports.com" || cfg.ProofKey != testProofKey {
		t.Errorf("round trip lost the prober settings: %+v", cfg)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "which public addresses this host") {
		t.Error("the file must say what the prober server is told")
	}
}

func TestWriteConfigRefusesHalfTheProberSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	err := WriteConfig(path, Config{Server: "https://cp.example.test", Credential: testCredential,
		ProberServer: "https://app.whichports.com"})
	if err == nil {
		t.Fatal("half the prober settings was written")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("a refused write left a file behind")
	}
}

func proberClient(serverURL string) *Client {
	return NewClient(Config{Server: "https://cp.example.test", Credential: testCredential,
		AllowHTTP: true, ProberServer: serverURL, ProofKey: testProofKey})
}

var claimed = []netip.Addr{netip.MustParseAddr("185.199.108.153"),
	netip.MustParseAddr("2606:50c0:8000::153")}

type recorded struct {
	path, method, auth, contentType string
	body                            []byte
}

func recorder(t *testing.T, status int, answer []byte) (*httptest.Server, *[]recorded) {
	t.Helper()
	var mu sync.Mutex
	var seen []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		buf.ReadFrom(r.Body)
		mu.Lock()
		seen = append(seen, recorded{r.URL.Path, r.Method, r.Header.Get("Authorization"),
			r.Header.Get("Content-Type"), buf.Bytes()})
		mu.Unlock()
		w.WriteHeader(status)
		w.Write(answer)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// The server listens on 127.0.0.1, so tcp4 reaches it and tcp6 cannot dial,
// which is a single-stack host and is not an error.
func TestProveToProberSendsTheAddressesAndNothingElse(t *testing.T) {
	srv, seen := recorder(t, http.StatusNoContent, nil)
	if got := proberClient(srv.URL).ProveToProber(context.Background(), claimed); got != 1 {
		t.Fatalf("answered = %d, want 1 over tcp4", got)
	}
	if len(*seen) != 1 {
		t.Fatalf("requests = %d, want 1", len(*seen))
	}
	r := (*seen)[0]
	if r.path != "/api/v1/prober/presence" || r.method != http.MethodPost {
		t.Errorf("sent %s %s", r.method, r.path)
	}
	if r.auth != "Bearer "+testProofKey {
		t.Errorf("authorization = %q, want the proof key and never the host credential", r.auth)
	}
	want := `{"interface_addresses":["185.199.108.153","2606:50c0:8000::153"]}`
	if string(r.body) != want {
		t.Errorf("body = %s, want %s", r.body, want)
	}
	if bytes.Contains(r.body, []byte(testCredential)) {
		t.Error("the host credential reached the prober API")
	}
}

func TestProveToProberSendsNothingWhenNotConfigured(t *testing.T) {
	srv, seen := recorder(t, http.StatusNoContent, nil)
	client := NewClient(Config{Server: srv.URL, Credential: testCredential, AllowHTTP: true})
	if got := client.ProveToProber(context.Background(), claimed); got != 0 {
		t.Errorf("answered = %d", got)
	}
	if len(*seen) != 0 {
		t.Errorf("an unconfigured host sent %d requests", len(*seen))
	}
}

func TestProveToProberSendsNothingWithNoAddresses(t *testing.T) {
	srv, seen := recorder(t, http.StatusNoContent, nil)
	proberClient(srv.URL).ProveToProber(context.Background(), nil)
	if len(*seen) != 0 {
		t.Errorf("sent %d requests with nothing to claim", len(*seen))
	}
}

func TestProveToProberReadsNothingItIsAnswered(t *testing.T) {
	srv, _ := recorder(t, http.StatusInternalServerError,
		bytes.Repeat([]byte("act on this "), 100_000))
	if got := proberClient(srv.URL).ProveToProber(context.Background(), claimed); got != 0 {
		t.Errorf("answered = %d, want 0 on a 500", got)
	}
}

func TestProveToProberNeverFollowsARedirect(t *testing.T) {
	target, landed := recorder(t, http.StatusNoContent, nil)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/v1/prober/presence", http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()
	proberClient(redirecting.URL).ProveToProber(context.Background(), claimed)
	if len(*landed) != 0 {
		t.Error("a redirect was followed, carrying the proof key somewhere else")
	}
}

func TestPresenceBodyStopsAtTheLimit(t *testing.T) {
	var many []netip.Addr
	for i := 1; i <= MaxClaimedAddresses+10; i++ {
		many = append(many, netip.AddrFrom4([4]byte{185, 199, 108, byte(i)}))
	}
	if got := strings.Count(string(presenceBody(many)), `"185.`); got != MaxClaimedAddresses {
		t.Errorf("body carries %d addresses, want %d", got, MaxClaimedAddresses)
	}
}
