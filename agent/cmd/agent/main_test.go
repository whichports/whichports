package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whichports/whichports/agent/internal/report"
)

// The run-mode surface is a contract: stdout must print a valid document and
// nothing else, oneshot must refuse to pretend when the host is not enrolled,
// timer must keep the local file fresh whether or not delivery works, and an
// unknown mode must error. A fixed timestamp is injected so output is
// deterministic.

const testCredential = "whp_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// paths returns a config path and a state path inside a temp dir, so no test
// ever touches /etc or /var on the machine running the suite.
func paths(t *testing.T) (configPath, statePath string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "agent.conf"), filepath.Join(dir, "host.json")
}

// enrollAt writes a valid config pointing at a test server.
func enrollAt(t *testing.T, configPath, serverURL string) {
	t.Helper()
	err := report.WriteConfig(configPath, report.Config{
		Server: serverURL, Credential: testCredential, AllowHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestStdoutModeEmitsValidDocument(t *testing.T) {
	configPath, statePath := paths(t)
	var buf bytes.Buffer
	if err := run("stdout", &buf, 12345, configPath, statePath); err != nil {
		t.Fatalf("stdout mode failed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("stdout mode must print valid JSON, got error %v and output:\n%s", err, buf.String())
	}
	if doc["schema_version"] == nil {
		t.Fatal("the printed document must carry a schema_version")
	}
	if doc["collected_at_unix"].(float64) != 12345 {
		t.Fatal("the injected timestamp must be used, not the wall clock")
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stdout mode must not write the state file")
	}
}

func TestOneshotRefusesWhenNotEnrolled(t *testing.T) {
	configPath, statePath := paths(t)
	var buf bytes.Buffer
	err := run("oneshot", &buf, 1, configPath, statePath)
	if !errors.Is(err, report.ErrNotEnrolled) {
		t.Fatalf("oneshot without enrollment must say so, got %v", err)
	}
}

func TestOneshotDeliversTheDocument(t *testing.T) {
	var received []byte
	presence := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		buf.ReadFrom(r.Body)
		// The report, then one presence request per family the host can
		// dial: the test server is on 127.0.0.1, so exactly one, and empty.
		if r.URL.Path == "/api/v1/reports/presence" {
			presence++
			if buf.Len() != 0 {
				t.Errorf("a presence request carried %d bytes, want none", buf.Len())
			}
		} else {
			received = buf.Bytes()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	configPath, statePath := paths(t)
	enrollAt(t, configPath, srv.URL)
	var out bytes.Buffer
	if err := run("oneshot", &out, 777, configPath, statePath); err != nil {
		t.Fatalf("oneshot failed: %v", err)
	}
	if presence != 1 {
		t.Errorf("presence requests = %d, want 1 over tcp4 to a 127.0.0.1 server", presence)
	}
	var doc map[string]any
	if err := json.Unmarshal(received, &doc); err != nil {
		t.Fatalf("the control plane must receive valid JSON: %v", err)
	}
	if doc["collected_at_unix"].(float64) != 777 {
		t.Fatal("the delivered document does not carry the injected timestamp")
	}
	if out.Len() != 0 {
		t.Errorf("oneshot printed %q, success should be silent for cron", out.String())
	}
}

func TestTimerWritesLocalFileWhenNotEnrolled(t *testing.T) {
	configPath, statePath := paths(t)
	var buf bytes.Buffer
	if err := run("timer", &buf, 42, configPath, statePath); err != nil {
		t.Fatalf("timer on an un-enrolled host must succeed locally: %v", err)
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("timer must write the state file: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("state file is not valid JSON: %v", err)
	}
	assertNoLeftovers(t, statePath)
}

// assertNoLeftovers fails if anything other than the state file itself is
// left in the state directory. The temp file has an unpredictable name now,
// so checking one fixed name would no longer prove the cleanup happened.
func assertNoLeftovers(t *testing.T, statePath string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(statePath))
	if err != nil {
		t.Fatalf("read state dir: %v", err)
	}
	for _, e := range entries {
		if filepath.Join(filepath.Dir(statePath), e.Name()) != statePath {
			t.Errorf("leftover in the state directory after a run: %s", e.Name())
		}
	}
}

// The document names every listening port and the process behind it, so it
// must not be world-readable regardless of the umask the run inherited.
func TestStateFileIsNotWorldReadable(t *testing.T) {
	configPath, statePath := paths(t)
	var buf bytes.Buffer
	if err := run("timer", &buf, 42, configPath, statePath); err != nil {
		t.Fatalf("timer failed: %v", err)
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != stateFileMode {
		t.Errorf("state file mode = %#o, want %#o", perm, stateFileMode)
	}
}

// A symlink sitting where the temp file would go must not redirect the write.
// The agent runs as root, so a followed link would mean root writing the
// document to a path someone else chose. os.CreateTemp opens with O_EXCL and
// an unpredictable name, so there is nothing to pre-place.
func TestStateWriteIgnoresAPlantedSymlink(t *testing.T) {
	configPath, statePath := paths(t)
	dir := filepath.Dir(statePath)
	target := filepath.Join(t.TempDir(), "attacker-chosen")

	// The name the previous implementation used, planted as a link.
	if err := os.Symlink(target, statePath+".tmp"); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := run("timer", &buf, 42, configPath, statePath); err != nil {
		t.Fatalf("timer failed: %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the document was written through a planted symlink to %s", target)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Errorf("the real state file was not written: %v", err)
	}
	// The planted link is not ours to clean up, but nothing else may remain.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := filepath.Join(dir, e.Name())
		if name != statePath && name != statePath+".tmp" {
			t.Errorf("leftover in the state directory: %s", e.Name())
		}
	}
}

func TestTimerDeliversWhenEnrolled(t *testing.T) {
	delivered := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	configPath, statePath := paths(t)
	enrollAt(t, configPath, srv.URL)
	var buf bytes.Buffer
	if err := run("timer", &buf, 42, configPath, statePath); err != nil {
		t.Fatalf("timer failed: %v", err)
	}
	if !delivered {
		t.Fatal("an enrolled timer run must deliver the document")
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatal("the local state file must be written even when delivering")
	}
}

// A control plane outage must fail the unit loudly, but the local file must
// already be fresh: local truth first, then the network.
func TestTimerKeepsLocalFileWhenDeliveryFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	configPath, statePath := paths(t)
	enrollAt(t, configPath, srv.URL)
	var buf bytes.Buffer
	err := run("timer", &buf, 42, configPath, statePath)
	if err == nil {
		t.Fatal("a failed delivery must surface as an error so the unit shows failed")
	}
	if _, statErr := os.Stat(statePath); statErr != nil {
		t.Fatal("the state file must be written before delivery is attempted")
	}
}

func TestUnknownModeErrors(t *testing.T) {
	configPath, statePath := paths(t)
	var buf bytes.Buffer
	if err := run("banana", &buf, 1, configPath, statePath); err == nil {
		t.Fatal("an unknown mode must return an error")
	}
}

// --- enroll ---

func TestEnrollWritesConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "agent.conf")
	var out bytes.Buffer
	err := runEnroll([]string{"--server=https://app.example.test", "--credential=" + testCredential}, configPath, &out)
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}
	cfg, err := report.Load(configPath)
	if err != nil {
		t.Fatalf("enroll wrote a config Load refuses: %v", err)
	}
	if cfg.Server != "https://app.example.test" {
		t.Errorf("server = %q", cfg.Server)
	}
	if !strings.Contains(out.String(), "whichports-agent.timer") {
		t.Errorf("enroll should tell the operator the next step, said %q", out.String())
	}
}

func TestEnrollRequiresBothFlags(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "agent.conf")
	var out bytes.Buffer
	if err := runEnroll([]string{"--server=https://x.test"}, configPath, &out); err == nil {
		t.Error("enroll without --credential must error")
	}
	if err := runEnroll([]string{"--credential=" + testCredential}, configPath, &out); err == nil {
		t.Error("enroll without --server must error")
	}
	if _, err := os.Stat(configPath); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused enrollment must not leave a config file behind")
	}
}

// failWriter always errors, to prove a write failure surfaces rather than
// being swallowed. An agent that cannot emit its document must say so.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errWrite }

var errWrite = &writeError{}

type writeError struct{}

func (*writeError) Error() string { return "write failed" }

func TestStdoutWriteFailureSurfaces(t *testing.T) {
	configPath, statePath := paths(t)
	if err := run("stdout", failWriter{}, 1, configPath, statePath); err == nil {
		t.Fatal("a failed write must surface as an error")
	}
}

// --- the prober API, for a self-hosted control plane ---

const testProofKey = "whpp_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// The prober API hears first, so a new host's first scan finds its address
// proved, then the report, then the presence to the host's own control plane.
func TestDeliverProvesToTheProberBeforeTheReport(t *testing.T) {
	var order []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	client := report.NewClient(report.Config{Server: srv.URL, Credential: testCredential,
		AllowHTTP: true, ProberServer: srv.URL, ProofKey: testProofKey})
	if err := deliver(client, document("185.199.108.153")); err != nil {
		t.Fatal(err)
	}
	want := []string{"/api/v1/prober/presence", "/api/v1/reports", "/api/v1/reports/presence"}
	if strings.Join(order, " ") != strings.Join(want, " ") {
		t.Errorf("order = %v, want %v", order, want)
	}
}

// A prober API that is down never fails the run: the report is what can.
func TestAProberAPIThatIsDownDoesNotFailTheRun(t *testing.T) {
	var reports int
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/reports" {
			reports++
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cp.Close()
	client := report.NewClient(report.Config{Server: cp.URL, Credential: testCredential,
		AllowHTTP: true, ProberServer: "http://127.0.0.1:9", ProofKey: testProofKey})
	if err := deliver(client, document("185.199.108.153")); err != nil {
		t.Fatalf("the run failed because the prober API was down: %v", err)
	}
	if reports != 1 {
		t.Errorf("reports = %d, want 1", reports)
	}
}

func TestEnrollWritesTheProberSettings(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "agent.conf")
	var out bytes.Buffer
	err := runEnroll([]string{"--server=https://cp.example.test", "--credential=" + testCredential,
		"--prober-server=https://app.whichports.com", "--prober-proof-key=" + testProofKey},
		configPath, &out)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := report.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProberServer != "https://app.whichports.com" || cfg.ProofKey != testProofKey {
		t.Errorf("enroll lost the prober settings: %+v", cfg)
	}
	if !strings.Contains(out.String(), "public addresses will be proved to https://app.whichports.com") {
		t.Errorf("enroll should say where the addresses go, said %q", out.String())
	}
}

func TestEnrollRefusesHalfTheProberFlags(t *testing.T) {
	for _, extra := range []string{"--prober-server=https://app.whichports.com",
		"--prober-proof-key=" + testProofKey} {
		configPath := filepath.Join(t.TempDir(), "agent.conf")
		var out bytes.Buffer
		err := runEnroll([]string{"--server=https://cp.example.test",
			"--credential=" + testCredential, extra}, configPath, &out)
		if err == nil {
			t.Errorf("enroll with only %s succeeded", extra)
		}
		if _, statErr := os.Stat(configPath); statErr == nil {
			t.Errorf("enroll with only %s left a config behind", extra)
		}
	}
}

// Stdout mode is the one a stranger runs first, so what is said about it has
// to be exactly true. For months the README and this command's own header
// said it "opens no connection, ever". It does: collecting the containers
// section dials the Docker and Podman unix sockets and sends one GET each
// (internal/collect/containers.go). Both connections are local, so the true
// sentence is that it sends nothing off the machine. This holds the four
// places a person reads to that sentence, and to never saying the old one.
func TestWhatIsSaidAboutStdoutModeIsWhatItDoes(t *testing.T) {
	places := map[string]string{
		"main.go":                                "send nothing off the machine",
		"../../README.md":                        "send nothing off the",
		"../../packaging/nfpm.yaml":              "in stdout mode sends nothing off the machine",
		"../../packaging/scripts/postinstall.sh": "sends nothing off this machine",
	}
	for path, want := range places {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		text := string(data)
		if !strings.Contains(text, want) {
			t.Errorf("%s no longer says %q about stdout mode", path, want)
		}
		for _, wrong := range []string{"opens no connection", "sends nothing anywhere",
			"Reads no config", "reads no config", "(prints the document, sends nothing)"} {
			if strings.Contains(text, wrong) {
				t.Errorf("%s says %q, which stdout mode does not live up to: it sends "+
					"one GET to each container runtime's local socket", path, wrong)
			}
		}
	}
}
