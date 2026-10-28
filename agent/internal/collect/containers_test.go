package collect

// The container collector's review. No sockets and no daemons: a canned
// http.RoundTripper stands in for the runtime, so every response shape is
// exact, including the hostile ones. The response fixture follows the
// container-list JSON both runtimes serve on their compat endpoint.

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

type cannedTransport struct {
	status int
	body   string
	err    error
}

func (c cannedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &http.Response{
		StatusCode: c.status,
		Body:       io.NopCloser(strings.NewReader(c.body)),
	}, nil
}

func cannedClient(status int, body string) *http.Client {
	return &http.Client{Transport: cannedTransport{status: status, body: body}}
}

const dockerListJSON = `[
  {"Id":"beef1234beef","Names":["/web"],"Image":"nginx:1.27",
   "Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},
            {"PrivatePort":9000,"Type":"tcp"},
            {"IP":"127.0.0.1","PrivatePort":81,"PublicPort":8081,"Type":"tcp"}]},
  {"Id":"cafe5678cafe","Names":["/db"],"Image":"postgres:17","Ports":[]}
]`

func TestContainersHappyPath(t *testing.T) {
	got, verdict := queryContainers(cannedClient(200, dockerListJSON))
	if verdict.Status != hostdoc.StatusCollected {
		t.Fatalf("verdict = %+v, want collected", verdict)
	}
	// Sorted by name: db before web. The unpublished 9000 is dropped, the
	// two published ports are sorted by host port, and the leading slash on
	// names is trimmed.
	if len(got) != 2 || got[0].Name != "db" || got[1].Name != "web" {
		t.Fatalf("containers wrong: %+v", got)
	}
	web := got[1]
	if web.ID != "beef1234beef" || web.Image != "nginx:1.27" {
		t.Fatalf("web identity wrong: %+v", web)
	}
	wantPorts := []hostdoc.PublishedPort{
		{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		{HostIP: "127.0.0.1", HostPort: 8081, ContainerPort: 81, Protocol: "tcp"},
	}
	if len(web.Ports) != len(wantPorts) {
		t.Fatalf("ports = %+v, want %+v", web.Ports, wantPorts)
	}
	for i := range wantPorts {
		if web.Ports[i] != wantPorts[i] {
			t.Errorf("ports[%d] = %+v, want %+v", i, web.Ports[i], wantPorts[i])
		}
	}
	if len(got[0].Ports) != 0 {
		t.Fatalf("db should publish nothing: %+v", got[0].Ports)
	}
}

func TestContainersEmptyListIsCollected(t *testing.T) {
	got, verdict := queryContainers(cannedClient(200, "[]"))
	if verdict.Status != hostdoc.StatusCollected || len(got) != 0 {
		t.Fatalf("empty list: %+v %+v", got, verdict)
	}
}

func TestContainersHostileNamesSanitized(t *testing.T) {
	// Control characters arrive JSON-escaped, which is the only way valid
	// JSON can carry them; the decoder turns them back into real bytes.
	hostile := `[{"Id":"abc","Names":["/ev\u001b[31mil"],"Image":"img\u0007:x",
	  "Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"}]}]`
	got, verdict := queryContainers(cannedClient(200, hostile))
	if verdict.Status != hostdoc.StatusCollected || len(got) != 1 {
		t.Fatalf("hostile parse failed: %+v %+v", got, verdict)
	}
	if got[0].Name != "ev?[31mil" || got[0].Image != "img?:x" {
		t.Fatalf("names not sanitized: %+v", got[0])
	}
	d := hostdoc.New("h", 1)
	d.Containers = &hostdoc.ContainersSection{
		Section: hostdoc.Section{Status: hostdoc.StatusCollected},
		Sources: map[string]hostdoc.Section{"docker": {Status: hostdoc.StatusCollected}},
		Docker:  got,
	}
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, b)
}

func TestContainersAPIFailuresAreTyped(t *testing.T) {
	if _, v := queryContainers(cannedClient(500, "boom")); v.Status != hostdoc.StatusReadError || v.Cause != hostdoc.CauseParseFailed {
		t.Fatalf("non-200 verdict = %+v", v)
	}
	if _, v := queryContainers(cannedClient(200, "{not json")); v.Status != hostdoc.StatusReadError || v.Cause != hostdoc.CauseParseFailed {
		t.Fatalf("bad json verdict = %+v", v)
	}
	broken := &http.Client{Transport: cannedTransport{err: errors.New("connection refused")}}
	if _, v := queryContainers(broken); v.Status != hostdoc.StatusReadError || v.Cause != hostdoc.CauseSocketError {
		t.Fatalf("refused verdict = %+v", v)
	}
	hung := &http.Client{Transport: cannedTransport{err: timeoutErr{}}}
	if _, v := queryContainers(hung); v.Status != hostdoc.StatusReadError || v.Cause != hostdoc.CauseTimeout {
		t.Fatalf("timeout verdict = %+v", v)
	}
}

// timeoutErr satisfies net.Error the way a dial timeout does.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

// A socket the agent is not allowed to connect to must read as
// permission_denied, not as a broken daemon. The unprivileged case is the
// common one: /var/run/docker.sock is root:docker 0660, so anyone outside the
// group gets EACCES from connect(2), and calling that a socket error blames
// the daemon for the agent's own lack of access.
//
// The error is built as the standard library really wraps it, url.Error round
// net.OpError round os.SyscallError round the errno, because the fix depends
// on errors.Is reaching all the way down that chain.
func TestContainersPermissionDeniedIsNotASocketError(t *testing.T) {
	denied := &url.Error{
		Op:  "Get",
		URL: "http://unix/containers/json",
		Err: &net.OpError{
			Op:   "dial",
			Net:  "unix",
			Addr: &net.UnixAddr{Name: "/var/run/docker.sock", Net: "unix"},
			Err:  os.NewSyscallError("connect", syscall.EACCES),
		},
	}
	client := &http.Client{Transport: cannedTransport{err: denied}}
	_, v := queryContainers(client)
	if v.Status != hostdoc.StatusPermissionDenied || v.Cause != hostdoc.CausePermission {
		t.Fatalf("EACCES on the runtime socket = %+v, want permission_denied/permission", v)
	}
}

// EPERM is the other errno the same connect can return, and it must classify
// the same way.
func TestContainersEPERMIsPermissionDenied(t *testing.T) {
	client := &http.Client{Transport: cannedTransport{err: os.NewSyscallError("connect", syscall.EPERM)}}
	if _, v := queryContainers(client); v.Status != hostdoc.StatusPermissionDenied {
		t.Fatalf("EPERM verdict = %+v, want permission_denied", v)
	}
}

// A timeout must still win over the permission branch, because a hung daemon
// and a refused one are different findings and the order of the checks is
// what keeps them apart.
func TestContainersTimeoutIsNotReclassifiedAsPermission(t *testing.T) {
	client := &http.Client{Transport: cannedTransport{err: timeoutErr{}}}
	if _, v := queryContainers(client); v.Cause != hostdoc.CauseTimeout {
		t.Fatalf("timeout verdict = %+v, want timeout", v)
	}
}

func TestContainersOversizedResponseIsParseError(t *testing.T) {
	// A response past the read cap gets truncated mid-stream, which must
	// surface as a parse failure, never as a silently shortened list.
	var b strings.Builder
	b.WriteString("[")
	for b.Len() < containerResponseLimit+1024 {
		b.WriteString(`{"Id":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},`)
	}
	b.WriteString(`{"Id":"y"}]`)
	if _, v := queryContainers(cannedClient(200, b.String())); v.Status != hostdoc.StatusReadError || v.Cause != hostdoc.CauseParseFailed {
		t.Fatalf("oversized verdict = %+v", v)
	}
}

func TestContainersNoSocketsIsNotPresent(t *testing.T) {
	sec := CollectContainers(t.TempDir())
	if sec.Status != hostdoc.StatusNotPresent {
		t.Fatalf("status = %q, want not_present", sec.Status)
	}
	for _, k := range hostdoc.ContainerSources {
		if sec.Sources[k].Status != hostdoc.StatusNotPresent {
			t.Fatalf("source %s = %+v, want not_present", k, sec.Sources[k])
		}
	}
}

func TestContainersStaleSocketIsSocketError(t *testing.T) {
	// A plain file squatting on the socket path: the stat succeeds, the dial
	// fails, and the verdict must say the conversation failed rather than
	// pretend the runtime is absent.
	root := t.TempDir()
	sockPath := filepath.Join(root, "run/podman/podman.sock")
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sockPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	sec := CollectContainers(root)
	if got := sec.Sources["podman"]; got.Status != hostdoc.StatusReadError || got.Cause != hostdoc.CauseSocketError {
		t.Fatalf("podman verdict = %+v, want read_error/socket_error", got)
	}
	if got := sec.Sources["docker"]; got.Status != hostdoc.StatusNotPresent {
		t.Fatalf("docker verdict = %+v, want not_present", got)
	}
	if sec.Status != hostdoc.StatusReadError {
		t.Fatalf("section = %q, want read_error", sec.Status)
	}
}

func TestContainersDeterministic(t *testing.T) {
	a, _ := queryContainers(cannedClient(200, dockerListJSON))
	b, _ := queryContainers(cannedClient(200, dockerListJSON))
	d1 := hostdoc.New("h", 1)
	d1.Containers = &hostdoc.ContainersSection{Section: hostdoc.Section{Status: hostdoc.StatusCollected}, Docker: a}
	d2 := hostdoc.New("h", 1)
	d2.Containers = &hostdoc.ContainersSection{Section: hostdoc.Section{Status: hostdoc.StatusCollected}, Docker: b}
	m1, err1 := hostdoc.Marshal(d1)
	m2, err2 := hostdoc.Marshal(d2)
	if err1 != nil || err2 != nil {
		t.Fatalf("marshal errors: %v %v", err1, err2)
	}
	if !bytes.Equal(m1, m2) {
		t.Fatal("two identical container states differ")
	}
}
