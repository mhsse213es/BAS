package webgwefficacy

import (
	"testing"
	"time"
)

func mustCatalog(t *testing.T) []TestDestination {
	t.Helper()
	cat, err := AudspectWebGWDestinationCatalog()
	if err != nil {
		t.Fatalf("AudspectWebGWDestinationCatalog: %v", err)
	}
	return cat
}

func TestWebGWCatalog_BuildsWithoutError(t *testing.T) {
	if n := len(mustCatalog(t)); n != 43 {
		t.Fatalf("catalog has %d destinations, want 43", n)
	}
}

func TestWebGWCatalog_IDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range mustCatalog(t) {
		if seen[d.ID] {
			t.Errorf("duplicate destination ID %q", d.ID)
		}
		seen[d.ID] = true
	}
}

// Every category must hold both a known-bad destination (the gateway must
// stop it) and a known-good destination (the gateway must allow it). A
// category with only one side cannot distinguish a working control from a
// control that blocks everything or allows everything.
func TestWebGWCatalog_EveryCategoryHasBadAndGoodPair(t *testing.T) {
	bad := map[DestinationCategory]int{}
	good := map[DestinationCategory]int{}
	for _, d := range mustCatalog(t) {
		if d.ExpectedAction == ExpectedAllow {
			good[d.Category]++
		} else {
			bad[d.Category]++
		}
	}
	for _, c := range []DestinationCategory{CategoryPhishing, CategoryC2, CategoryURLFilter, CategorySafeFile} {
		if bad[c] == 0 {
			t.Errorf("category %q has no known-bad destination", c)
		}
		if good[c] == 0 {
			t.Errorf("category %q has no known-good destination", c)
		}
	}
}

// Each destination is exercised through the existing verifier in both
// directions: gateway evidence matching the expectation must Pass, and
// evidence showing the opposite action must Fail. Without the second half a
// verifier that always passes would look healthy.
func TestWebGWCatalog_EveryDestinationVerifiesBothWays(t *testing.T) {
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	for _, d := range mustCatalog(t) {
		exp := d.Expectation("cloudflare-gateway")
		opposite := "allow"
		if d.ExpectedAction == ExpectedAllow {
			opposite = "block"
		}
		cases := []struct {
			name, action string
			wantVerdict  WebGWVerdict
		}{
			{"matching-action", string(d.ExpectedAction), VerdictPass},
			{"opposite-action", opposite, VerdictFail},
		}
		for _, c := range cases {
			provider := NewFixtureGatewayProvider([]GatewayEvidence{
				{RequestURL: d.URL, Action: c.action, Category: d.URLCategory, PolicyRule: "fixture", Timestamp: now, Source: SourceFixture},
			})
			result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)
			if result.Prevention.Verdict != c.wantVerdict {
				t.Errorf("%s %s: Prevention = %q, want %q (%s)", d.ID, c.name, result.Prevention.Verdict, c.wantVerdict, result.Prevention.Reason)
			}
		}
	}
}

func TestNewTestDestination_RejectsUnsafeInput(t *testing.T) {
	cases := []struct {
		name     string
		category DestinationCategory
		url      string
		expected ExpectedGatewayAction
		note     string
	}{
		{"real public domain", CategoryPhishing, "https://www.google.com/", ExpectedBlock, "n"},
		{"public IP literal", CategoryC2, "https://93.184.216.34/beacon", ExpectedBlock, "n"},
		{"private IP literal", CategoryC2, "https://10.0.0.5/beacon", ExpectedBlock, "n"},
		{"userinfo in URL", CategoryPhishing, "https://user:pass@login.lab.test/", ExpectedBlock, "n"},
		{"non-http scheme", CategoryPhishing, "ftp://login.lab.test/", ExpectedBlock, "n"},
		{"unknown category", DestinationCategory("gambling"), "https://x.lab.test/", ExpectedBlock, "n"},
		{"unknown expected action", CategoryPhishing, "https://x.lab.test/", ExpectedGatewayAction("maybe"), "n"},
		{"empty note", CategoryPhishing, "https://x.lab.test/", ExpectedBlock, "  "},
		{"EICAR-like name not permitted", CategorySafeFile, "https://files.download-lab.test/payload.exe", ExpectedBlock, "n"},
		{"safe-file name with real domain", CategorySafeFile, "https://files.example.com/eicar.com", ExpectedBlock, "n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewTestDestination("WG-X-001", c.category, c.url, "cat", c.expected, c.note); err == nil {
				t.Errorf("NewTestDestination(%q) accepted an unsafe or malformed destination", c.url)
			}
		})
	}
}

func TestNewTestDestination_AcceptsReservedHostsAndPermittedFiles(t *testing.T) {
	if _, err := NewTestDestination("WG-OK-001", CategorySafeFile, "https://files.download-lab.test/eicar.com", "file-download", ExpectedBlock, "n"); err != nil {
		t.Errorf("valid EICAR destination rejected: %v", err)
	}
	if _, err := NewTestDestination("WG-OK-002", CategoryC2, "http://beacon.c2-lab.test/check-in", "cc", ExpectedBlock, "n"); err != nil {
		t.Errorf("valid reserved-host destination rejected: %v", err)
	}
}
