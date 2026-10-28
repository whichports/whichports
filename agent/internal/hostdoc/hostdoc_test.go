package hostdoc

import (
	"encoding/json"
	"strings"
	"testing"
)

// The tests are the review. For the document contract that
// means proving the invariants downstream code relies on: the envelope is
// stamped, sections fail independently, and no undefined typed value can ever be
// marshalled. Edge cases are deliberate: nil, empty, wrong version, each bad
// enum, and the collected/empty vs not-collected/nil distinction.

func TestNewStampsEnvelope(t *testing.T) {
	d := New("web-01", 1000)
	if d.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version = %d, want %d", d.SchemaVersion, SchemaVersion)
	}
	if d.Hostname != "web-01" {
		t.Fatalf("hostname = %q, want web-01", d.Hostname)
	}
	if d.CollectedAtUnix != 1000 {
		t.Fatalf("collected_at_unix = %d, want 1000", d.CollectedAtUnix)
	}
	if d.Sockets != nil {
		t.Fatalf("a new document must have no sections yet")
	}
}

func TestMarshalNilDocument(t *testing.T) {
	if _, err := Marshal(nil); err == nil {
		t.Fatal("Marshal(nil) must error, did not")
	}
}

func TestMarshalWrongSchemaVersion(t *testing.T) {
	d := New("h", 1)
	d.SchemaVersion = 999
	if _, err := Marshal(d); err == nil {
		t.Fatal("Marshal must reject an unexpected schema_version")
	}
}

func TestMarshalEmptyDocumentSucceeds(t *testing.T) {
	// A host with no sections collected yet is still a valid document. This is
	// the baseline that proves an empty read is not an error.
	d := New("h", 5)
	b, err := Marshal(d)
	if err != nil {
		t.Fatalf("empty document must marshal, got %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("output must be valid JSON: %v", err)
	}
	if round["schema_version"].(float64) != float64(SchemaVersion) {
		t.Fatal("marshalled document lost its schema_version")
	}
	if _, present := round["sockets"]; present {
		t.Fatal("a nil section must be omitted, not emitted as null")
	}
}

func TestCollectedEmptyIsDistinctFromNotCollected(t *testing.T) {
	// nil Sockets means we did not look. A non-nil section with an empty list
	// means we looked and found nothing. The document must preserve that
	// difference, because "no listeners" and "not measured" are not the same
	// claim (PRODUCT.md 4b).
	notCollected := New("h", 1)
	b1, err := Marshal(notCollected)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b1), "sockets") {
		t.Fatal("not-collected sockets must be absent from the JSON")
	}

	collectedEmpty := New("h", 1)
	collectedEmpty.Sockets = &SocketsSection{
		Section:   Section{Status: StatusCollected},
		Listening: []ListeningSocket{},
	}
	b2, err := Marshal(collectedEmpty)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b2), "sockets") {
		t.Fatal("collected-empty sockets must appear in the JSON with its status")
	}
	if !strings.Contains(string(b2), "\"status\": \"collected\"") {
		t.Fatal("collected section must carry its status")
	}
}

func TestSectionFailsIndependently(t *testing.T) {
	// The core resilience invariant: a permission error on one section must not
	// prevent the document, or any other section, from marshalling.
	d := New("h", 1)
	d.Sockets = &SocketsSection{
		Section: Section{Status: StatusPermissionDenied, Cause: CausePermission},
	}
	b, err := Marshal(d)
	if err != nil {
		t.Fatalf("a failed section must still marshal, got %v", err)
	}
	if !strings.Contains(string(b), "permission_denied") {
		t.Fatal("the failure status must be recorded, not swallowed")
	}
	if !strings.Contains(string(b), "\"cause\": \"permission\"") {
		t.Fatal("the typed cause must be recorded")
	}
}

func TestMarshalRejectsUndefinedStatus(t *testing.T) {
	// The fail-closed guarantee: an undefined status is a bug, and it must
	// surface as a marshalling error, never as an unknown string on the wire.
	d := New("h", 1)
	d.Sockets = &SocketsSection{Section: Section{Status: SectionStatus("made-up")}}
	if _, err := Marshal(d); err == nil {
		t.Fatal("Marshal must reject an undefined section status")
	}
}

func TestMarshalRejectsUndefinedCause(t *testing.T) {
	d := New("h", 1)
	d.Sockets = &SocketsSection{Section: Section{
		Status: StatusReadError,
		Cause:  ErrorCause("weird"),
	}}
	if _, err := Marshal(d); err == nil {
		t.Fatal("Marshal must reject an undefined error cause")
	}
}

func TestMarshalRejectsCollectedWithCause(t *testing.T) {
	// A collected section carries no cause. This catches the mistake of
	// stamping success while leaving a stale failure reason attached.
	d := New("h", 1)
	d.Sockets = &SocketsSection{Section: Section{
		Status: StatusCollected,
		Cause:  CausePermission,
	}}
	if _, err := Marshal(d); err == nil {
		t.Fatal("Marshal must reject a collected section that also has a cause")
	}
}

func TestMarshalRejectsUnknownSourceKey(t *testing.T) {
	// The sources map is keyed by the four proc net file names and nothing
	// else. A typo like "tpc" must fail the marshal, not ship.
	d := New("h", 1)
	d.Sockets = &SocketsSection{
		Section: Section{Status: StatusCollected},
		Sources: map[string]Section{"tpc": {Status: StatusCollected}},
	}
	if _, err := Marshal(d); err == nil {
		t.Fatal("Marshal must reject an unknown source key")
	}
}

func TestMarshalRejectsBadSourceSection(t *testing.T) {
	// Each per-source verdict obeys the same rules as a section: defined
	// enums only, and collected never carries a cause.
	bad := []Section{
		{Status: SectionStatus("made-up")},
		{Status: StatusCollected, Cause: CausePermission},
		{Status: StatusReadError, Cause: ErrorCause("weird")},
	}
	for i, s := range bad {
		d := New("h", 1)
		d.Sockets = &SocketsSection{
			Section: Section{Status: StatusCollected},
			Sources: map[string]Section{"tcp": s},
		}
		if _, err := Marshal(d); err == nil {
			t.Fatalf("case %d: Marshal must reject source section %+v", i, s)
		}
	}
}

func TestSourcesSurviveTheRoundTrip(t *testing.T) {
	// The honest-partial case: tcp collected, tcp6 unreadable. Both verdicts
	// must appear in the JSON so a reader can see which family to trust.
	d := New("h", 1)
	d.Sockets = &SocketsSection{
		Section: Section{Status: StatusCollected},
		Sources: map[string]Section{
			"tcp":  {Status: StatusCollected},
			"tcp6": {Status: StatusReadError, Cause: CauseParseFailed},
		},
		Listening: []ListeningSocket{},
	}
	b, err := Marshal(d)
	if err != nil {
		t.Fatalf("valid sources must marshal: %v", err)
	}
	var round Document
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	if round.Sockets.Sources["tcp6"].Cause != CauseParseFailed {
		t.Fatalf("tcp6 verdict lost in round trip: %+v", round.Sockets.Sources)
	}
}

// uidPtr gives the tests a literal for the optional owner uid.
func uidPtr(v int64) *int64 { return &v }

func TestMarshalRejectsBadSocketFields(t *testing.T) {
	cases := []struct {
		name   string
		socket ListeningSocket
	}{
		{"bad protocol", ListeningSocket{Protocol: "sctp", Family: "v4"}},
		{"bad family", ListeningSocket{Protocol: "tcp", Family: "v9"}},
		{"empty protocol", ListeningSocket{Protocol: "", Family: "v4"}},
		{"empty family", ListeningSocket{Protocol: "tcp", Family: ""}},
		// A uid is 32-bit unsigned on Linux, so values outside that range
		// were never read out of /proc and must fail closed.
		{"negative owner uid", ListeningSocket{Protocol: "tcp", Family: "v4", OwnerUID: uidPtr(-1)}},
		{"owner uid past 32 bits", ListeningSocket{Protocol: "tcp", Family: "v4", OwnerUID: uidPtr(4294967296)}},
		// The name is a lookup of the uid, so a name arriving without one is
		// a value nothing measured.
		{"owner name without a uid", ListeningSocket{Protocol: "tcp", Family: "v4", OwnerName: "caddy"}},
		{"owner name past the cap", ListeningSocket{Protocol: "tcp", Family: "v4",
			OwnerUID: uidPtr(80), OwnerName: strings.Repeat("a", MaxOwnerNameLen+1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := New("h", 1)
			d.Sockets = &SocketsSection{
				Section:   Section{Status: StatusCollected},
				Listening: []ListeningSocket{tc.socket},
			}
			if _, err := Marshal(d); err == nil {
				t.Fatalf("Marshal must reject %s", tc.name)
			}
		})
	}
}

func TestMarshalRejectsBadInterfaceAddressFields(t *testing.T) {
	// The same fail-closed rule the sockets section gets. The control plane
	// matches an interface address on both its family and its address, so a
	// section where either is missing or undefined must never leave the host.
	cases := []struct {
		name    string
		address InterfaceAddress
	}{
		{"bad family", InterfaceAddress{Interface: "eth0", Family: "v9", Address: "1.2.3.4"}},
		{"empty family", InterfaceAddress{Interface: "eth0", Family: "", Address: "1.2.3.4"}},
		{"empty address", InterfaceAddress{Interface: "eth0", Family: "v4", Address: ""}},
		{"empty interface", InterfaceAddress{Interface: "", Family: "v4", Address: "1.2.3.4"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := New("h", 1)
			d.InterfaceAddresses = &InterfaceAddressesSection{
				Section:   Section{Status: StatusCollected},
				Addresses: []InterfaceAddress{tc.address},
			}
			if _, err := Marshal(d); err == nil {
				t.Fatalf("Marshal must reject %s", tc.name)
			}
		})
	}
}

func TestInterfaceAddressesRoundTrip(t *testing.T) {
	d := New("web-01", 42)
	d.InterfaceAddresses = &InterfaceAddressesSection{
		Section: Section{Status: StatusCollected},
		Addresses: []InterfaceAddress{
			{Interface: "eth0", Family: "v4", Address: "185.199.108.153", Global: true},
			{Interface: "eth0", Family: "v6", Address: "2606:50c0:8000::153", Global: true},
			{Interface: "eth1", Family: "v4", Address: "10.0.0.5", Global: false},
		},
	}
	b, err := Marshal(d)
	if err != nil {
		t.Fatalf("valid document must marshal: %v", err)
	}
	if !strings.Contains(string(b), "\"global\": false") {
		t.Fatal("a false global must appear in the JSON, not be omitted")
	}
	var round Document
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	if round.InterfaceAddresses == nil || len(round.InterfaceAddresses.Addresses) != 3 {
		t.Fatalf("addresses lost in the round trip: %+v", round.InterfaceAddresses)
	}
	if round.InterfaceAddresses.Addresses[2].Global {
		t.Fatal("the private address must stay marked not global")
	}
}

func TestInterfaceAddressesCollectedEmptyIsDistinctFromNotCollected(t *testing.T) {
	// The same distinction the sockets section keeps. "This host holds no
	// addresses worth reporting" is a measured answer and must not read as
	// "we did not look".
	notCollected := New("h", 1)
	b1, err := Marshal(notCollected)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b1), "interface_addresses") {
		t.Fatal("a nil section must be absent from the JSON")
	}

	collectedEmpty := New("h", 1)
	collectedEmpty.InterfaceAddresses = &InterfaceAddressesSection{
		Section:   Section{Status: StatusCollected},
		Addresses: []InterfaceAddress{},
	}
	b2, err := Marshal(collectedEmpty)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b2), "\"addresses\": []") {
		t.Fatalf("collected and empty must be an empty list in the JSON:\n%s", b2)
	}
}

func TestInterfaceAddressesFailsIndependently(t *testing.T) {
	// A denied read carries its own status and never blanks the rest of the
	// document, and a partial list is still carried beside the failure.
	d := New("h", 1)
	d.Sockets = &SocketsSection{Section: Section{Status: StatusCollected}}
	d.InterfaceAddresses = &InterfaceAddressesSection{
		Section: Section{Status: StatusPermissionDenied, Cause: CausePermission},
		Addresses: []InterfaceAddress{
			{Interface: "eth0", Family: "v4", Address: "185.199.108.153", Global: true},
		},
	}
	b, err := Marshal(d)
	if err != nil {
		t.Fatalf("a failed section must still marshal: %v", err)
	}
	if !strings.Contains(string(b), "permission_denied") {
		t.Fatal("the failure status must be recorded")
	}
	if !strings.Contains(string(b), "185.199.108.153") {
		t.Fatal("the addresses that were read must survive beside the failure")
	}
}

func TestValidSocketRoundTrips(t *testing.T) {
	d := New("web-01", 42)
	d.Sockets = &SocketsSection{
		Section: Section{Status: StatusCollected},
		Listening: []ListeningSocket{
			{Protocol: "tcp", Family: "v4", BindAddress: "0.0.0.0", Port: 22, ProcessName: "sshd", PID: 900},
			{Protocol: "tcp", Family: "v6", BindAddress: "::", Port: 22, ProcessName: "sshd", PID: 900},
		},
	}
	b, err := Marshal(d)
	if err != nil {
		t.Fatalf("valid document must marshal: %v", err)
	}
	var round Document
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("must round-trip through JSON: %v", err)
	}
	if round.Sockets == nil || len(round.Sockets.Listening) != 2 {
		t.Fatal("both sockets must survive the round trip")
	}
	if round.Sockets.Listening[0].Family == round.Sockets.Listening[1].Family {
		t.Fatal("v4 and v6 sockets must stay distinct, not collapse")
	}
}

func TestSocketOwnerRoundTripsAndUIDZeroIsKept(t *testing.T) {
	// The owner fields at their boundaries: root at uid 0, which omitempty
	// would silently erase if the field were a plain int, the top of the
	// 32-bit range, and a uid with no name, the rootless-podman shape. All
	// three must marshal and survive the round trip unchanged.
	d := New("web-01", 42)
	d.Sockets = &SocketsSection{
		Section: Section{Status: StatusCollected},
		Listening: []ListeningSocket{
			{Protocol: "tcp", Family: "v4", BindAddress: "0.0.0.0", Port: 22,
				OwnerUID: uidPtr(0), OwnerName: "root"},
			{Protocol: "tcp", Family: "v4", BindAddress: "0.0.0.0", Port: 111,
				OwnerUID: uidPtr(4294967295), OwnerName: "nobody"},
			{Protocol: "tcp", Family: "v6", BindAddress: "::", Port: 18080,
				OwnerUID: uidPtr(1003)},
		},
	}
	b, err := Marshal(d)
	if err != nil {
		t.Fatalf("valid owners must marshal: %v", err)
	}
	if !strings.Contains(string(b), "\"owner_uid\": 0") {
		t.Fatal("uid 0 must appear in the JSON, not be omitted")
	}
	var round Document
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	got := round.Sockets.Listening
	if got[0].OwnerUID == nil || *got[0].OwnerUID != 0 || got[0].OwnerName != "root" {
		t.Fatalf("root owner lost in the round trip: %+v", got[0])
	}
	if got[1].OwnerUID == nil || *got[1].OwnerUID != 4294967295 {
		t.Fatalf("the top of the uid range must survive: %+v", got[1])
	}
	if got[2].OwnerUID == nil || *got[2].OwnerUID != 1003 || got[2].OwnerName != "" {
		t.Fatalf("a bare uid must stay bare: %+v", got[2])
	}
}

func TestAnOldDocumentWithoutOwnerFieldsStillReads(t *testing.T) {
	// The fleet runs 0.1.5, whose sockets carry no owner fields. A document
	// of that shape must unmarshal into this package with the owner honestly
	// absent, not zero-valued into "root".
	old := `{"schema_version": 1, "hostname": "h", "collected_at_unix": 1,
	  "sockets": {"status": "collected", "listening": [
	    {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 22}]}}`
	var round Document
	if err := json.Unmarshal([]byte(old), &round); err != nil {
		t.Fatal(err)
	}
	s := round.Sockets.Listening[0]
	if s.OwnerUID != nil || s.OwnerName != "" {
		t.Fatalf("an absent owner must stay absent: %+v", s)
	}
}

// The marshaller accepts every Listen directive the collector can record.
//
// This test exists because it did not, and because a Mac cannot notice. The
// validator allowed only ListenStream and ListenDatagram. When the collector
// began recording all eight, every run on a host with a ListenFIFO= unit
// failed to marshal its document at all, which is the whole report lost rather
// than one field. macOS has no systemd unit files, so the collector found
// nothing there and the validator was never handed one. CI on Linux failed on
// the first push, on cloud-init-hotplugd.socket.
//
// Driving the validator directly is what makes it catchable on any machine.
func TestMarshalAcceptsEveryListenDirective(t *testing.T) {
	for _, directive := range SocketUnitListenDirectives {
		t.Run(directive, func(t *testing.T) {
			d := New("host", 1)
			d.SocketUnits = &SocketUnitsSection{
				Section: Section{Status: StatusCollected},
				Units: []SocketUnit{{
					Name: "u.socket", File: "/etc/systemd/system/u.socket",
					Origin: "admin", Source: "etc_systemd_system",
					Parsed: true, SocketSection: true,
					Listen: []SocketUnitListen{{
						Directive: directive, Value: "x", Kind: "not_an_internet_socket",
					}},
				}},
			}
			if _, err := Marshal(d); err != nil {
				t.Fatalf("Marshal rejected %s: %v", directive, err)
			}
		})
	}
}

// And it still refuses one it does not know, because a validator that accepts
// anything is not a validator.
func TestMarshalRefusesAnUnknownListenDirective(t *testing.T) {
	d := New("host", 1)
	d.SocketUnits = &SocketUnitsSection{
		Section: Section{Status: StatusCollected},
		Units: []SocketUnit{{
			Name: "u.socket", File: "/etc/systemd/system/u.socket",
			Origin: "admin", Source: "etc_systemd_system",
			Parsed: true, SocketSection: true,
			Listen: []SocketUnitListen{{Directive: "ListenTelepathy", Value: "x"}},
		}},
	}
	if _, err := Marshal(d); err == nil {
		t.Fatal("Marshal accepted a directive systemd does not define")
	}
}

// The agent version rides in the document under the additive rule: a reader
// keyed to a document without it keeps working. It exists because the fleet
// was upgraded and nothing in the product could confirm it (RECORD 4.89).
func TestAgentVersionIsCarriedWhenSet(t *testing.T) {
	d := New("web-01", 1000)
	d.AgentVersion = "0.1.6"
	b, err := Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"agent_version": "0.1.6"`) {
		t.Fatalf("agent_version missing from the document:\n%s", b)
	}
}

// A plain `go build` leaves the version empty, and an empty one is omitted
// rather than shipped as "" for a reader to puzzle over. That is the same
// posture --version takes when it prints unknown, and it is what keeps the
// field honest on a binary nobody stamped.
func TestAnUnstampedBinaryOmitsTheVersionRatherThanGuessing(t *testing.T) {
	b, err := Marshal(New("web-01", 1000))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "agent_version") {
		t.Fatalf("an unstamped binary named a version:\n%s", b)
	}
}
