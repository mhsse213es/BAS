// Command webgwprofile prints an industry profile's priority-coverage
// summary against Audspect's real, current WebGW coverage data --
// the first production caller of internal/webgwefficacy's
// IndustryProfile, answering "of the domains and data my industry
// cares about most, what's covered and what isn't."
package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/webgwefficacy"
)

var profileConstructors = map[string]func() (webgwefficacy.IndustryProfile, error){
	"bfsi":             webgwefficacy.BFSINBFCProfile,
	"healthcare":       webgwefficacy.HealthcareProfile,
	"manufacturing-ot": webgwefficacy.ManufacturingOTProfile,
	"msp":              webgwefficacy.MSPSharedTenantProfile,
}

func knownProfileNames() []string {
	names := make([]string, 0, len(profileConstructors))
	for name := range profileConstructors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// run resolves args[0] to a known industry profile, builds it, and
// writes its Describe() and PrioritySummary(report) output to stdout.
// report is passed in rather than fetched here so this function stays
// testable against a synthetic CoverageReport as well as the real
// AudspectWebGWCoverageReport.
func run(args []string, report webgwefficacy.CoverageReport, stdout io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: webgwprofile <profile-name>\nknown profiles: %s", strings.Join(knownProfileNames(), ", "))
	}
	ctor, ok := profileConstructors[args[0]]
	if !ok {
		return fmt.Errorf("unknown profile %q -- known profiles: %s", args[0], strings.Join(knownProfileNames(), ", "))
	}
	profile, err := ctor()
	if err != nil {
		return fmt.Errorf("building profile %q: %w", args[0], err)
	}

	fmt.Fprintln(stdout, profile.Describe())
	fmt.Fprintln(stdout, profile.PrioritySummary(report))
	return nil
}

func main() {
	report, err := webgwefficacy.AudspectWebGWCoverageReport()
	if err != nil {
		fmt.Fprintln(os.Stderr, "loading coverage report:", err)
		os.Exit(1)
	}
	if err := run(os.Args[1:], report, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
