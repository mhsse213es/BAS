package scenario

import (
	"strings"
	"testing"
)

// An ART input argument the atomic left without a default must resolve to a
// lab-safe value for known network targets (loopback), so a validation run
// executes against a harmless local target instead of a bogus placeholder path
// (e.g. T1046 "Port-Scanning /24 Subnet" ran against bas-placeholder-ip_address
// and errored).
func TestArtResolveArgs_SafeDefaultForNetworkTargets(t *testing.T) {
	cmd := artResolveArgs("scan #{ip_address}", map[string]artInputArg{"ip_address": {}}, "T1046", "Test 10")
	if strings.Contains(cmd, "bas-placeholder") {
		t.Fatalf("ip_address got a placeholder, want a safe default: %q", cmd)
	}
	if !strings.Contains(cmd, "127.0.0.1") {
		t.Fatalf("ip_address = %q, want it to contain 127.0.0.1", cmd)
	}

	// A subnet argument resolves to a harmless loopback CIDR.
	sub := artResolveArgs("scan #{subnet}", map[string]artInputArg{"subnet": {}}, "T1046", "x")
	if strings.Contains(sub, "bas-placeholder") || !strings.Contains(sub, "127.0.0") {
		t.Fatalf("subnet = %q, want a loopback default", sub)
	}

	// An atomic-declared default is still honoured untouched.
	if got := artResolveArgs("echo #{greeting}", map[string]artInputArg{"greeting": {Default: "hi"}}, "T1", "x"); got != "echo hi" {
		t.Fatalf("declared default not used: %q", got)
	}

	// An unknown arg with no default keeps the placeholder fallback (unchanged).
	if got := artResolveArgs("cat #{weird_arg}", map[string]artInputArg{"weird_arg": {}}, "T1", "x"); !strings.Contains(got, "bas-placeholder-weird_arg") {
		t.Fatalf("unknown arg should keep the placeholder: %q", got)
	}

	// Ambiguous or state-changing names must NOT get a network default. `port`
	// especially must never become a real port (445) — #{port} is often a LISTEN
	// / firewall-rule parameter that would open a real service on the host — and
	// target/destination/network/range/server/address are frequently file paths.
	// All keep the harmless placeholder fallback.
	for _, name := range []string{"port", "target", "destination", "network", "range", "server", "address"} {
		got := artResolveArgs("run #{"+name+"}", map[string]artInputArg{name: {}}, "T1", "x")
		if !strings.Contains(got, "bas-placeholder-"+name) {
			t.Errorf("arg %q = %q, want placeholder fallback (no network default)", name, got)
		}
	}
}
