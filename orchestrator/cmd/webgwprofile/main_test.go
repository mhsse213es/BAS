package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/webgwefficacy"
)

func TestRun_NoArgs_ReturnsUsageError(t *testing.T) {
	report, err := webgwefficacy.AudspectWebGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWebGWCoverageReport: %v", err)
	}
	var stdout bytes.Buffer

	err = run(nil, report, &stdout)

	if err == nil {
		t.Fatal("run: want a usage error for no arguments, got nil")
	}
	if !strings.Contains(err.Error(), "usage:") {
		t.Errorf("run error = %q, want it to contain usage instructions", err)
	}
}

func TestRun_UnknownProfileName_ReturnsError(t *testing.T) {
	report, err := webgwefficacy.AudspectWebGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWebGWCoverageReport: %v", err)
	}
	var stdout bytes.Buffer

	err = run([]string{"not-a-real-profile"}, report, &stdout)

	if err == nil {
		t.Fatal("run: want an error for an unknown profile name, got nil")
	}
	if !strings.Contains(err.Error(), "not-a-real-profile") {
		t.Errorf("run error = %q, want it to name the unknown profile", err)
	}
	if !strings.Contains(err.Error(), "bfsi") {
		t.Errorf("run error = %q, want it to list the known profile names", err)
	}
}

func TestRun_KnownProfile_WritesDescribeAndPrioritySummary(t *testing.T) {
	report, err := webgwefficacy.NewCoverageReport([]webgwefficacy.DomainCoverage{
		{DomainID: "03", DomainName: "DLP and web exfiltration", Status: webgwefficacy.CoverageCovered},
		{DomainID: "09", DomainName: "Configuration drift/administration", Status: webgwefficacy.CoverageCovered},
		{DomainID: "11", DomainName: "Availability/resilience", Status: webgwefficacy.CoverageCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	profile, err := webgwefficacy.BFSINBFCProfile()
	if err != nil {
		t.Fatalf("BFSINBFCProfile: %v", err)
	}
	var stdout bytes.Buffer

	if err := run([]string{"bfsi"}, report, &stdout); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := stdout.String()
	if !strings.Contains(got, profile.Describe()) {
		t.Errorf("stdout = %q, want it to contain Describe()'s output %q", got, profile.Describe())
	}
	if !strings.Contains(got, profile.PrioritySummary(report)) {
		t.Errorf("stdout = %q, want it to contain PrioritySummary()'s output", got)
	}
}

func TestRun_EveryKnownProfileName_Resolves(t *testing.T) {
	report, err := webgwefficacy.AudspectWebGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWebGWCoverageReport: %v", err)
	}

	for name := range profileConstructors {
		var stdout bytes.Buffer
		if err := run([]string{name}, report, &stdout); err != nil {
			t.Errorf("run(%q): %v", name, err)
		}
		if stdout.Len() == 0 {
			t.Errorf("run(%q): wrote nothing to stdout", name)
		}
	}
}
