package hostdoc

// The two fields added on 2026-09-12 for the unit behind a socket, and what
// the fail-closed marshaller refuses on them.

import (
	"encoding/json"
	"strings"
	"testing"
)

func socketWith(cgroup, unit string) *Document {
	d := New("h", 1)
	d.Sockets = &SocketsSection{
		Section: Section{Status: StatusCollected},
		Listening: []ListeningSocket{{Protocol: "tcp", Family: "v4", BindAddress: "0.0.0.0",
			Port: 443, Cgroup: cgroup, Unit: unit}},
	}
	return d
}

func TestCgroupAndUnitRoundTrip(t *testing.T) {
	b, err := Marshal(socketWith("/system.slice/caddy.service", "caddy.service"))
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Sockets struct {
			Listening []map[string]any `json:"listening"`
		} `json:"sockets"`
	}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	got := back.Sockets.Listening[0]
	if got["cgroup"] != "/system.slice/caddy.service" || got["unit"] != "caddy.service" {
		t.Errorf("got cgroup %v unit %v", got["cgroup"], got["unit"])
	}
}

func TestAnUnnamedSocketCarriesNeitherField(t *testing.T) {
	b, err := Marshal(socketWith("", ""))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"cgroup"`) || strings.Contains(string(b), `"unit"`) {
		t.Errorf("an empty answer was serialised as a field: %s", b)
	}
}

func TestACgroupPathWithNoUnitIsCarriedAlone(t *testing.T) {
	if _, err := Marshal(socketWith("/user.slice/user-0.slice", "")); err != nil {
		t.Fatalf("a path whose last element is a slice with no unit is a real answer: %v", err)
	}
}

func TestTheMarshallerRefusesAUnitTheCgroupDoesNotEndIn(t *testing.T) {
	cases := map[string]*Document{
		"unit with no cgroup":       socketWith("", "caddy.service"),
		"unit not the last element": socketWith("/system.slice/caddy.service/child", "caddy.service"),
		"unit unrelated":            socketWith("/system.slice/caddy.service", "sshd.service"),
		"relative cgroup":           socketWith("system.slice/caddy.service", "caddy.service"),
		"cgroup past the cap":       socketWith("/"+strings.Repeat("x", MaxCgroupPathLen), ""),
	}
	for name, d := range cases {
		if _, err := Marshal(d); err == nil {
			t.Errorf("%s: marshalled, want a refusal", name)
		}
	}
}

func TestSockDiagAndCgroup2AreAllowedSocketSources(t *testing.T) {
	d := socketWith("", "")
	d.Sockets.Sources = map[string]Section{
		"sock_diag": {Status: StatusCollected},
		"cgroup2":   {Status: StatusNotPresent},
	}
	if _, err := Marshal(d); err != nil {
		t.Fatal(err)
	}
}
