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
	"strings"

	"github.com/audspect/bas/internal/webgwefficacy"
)

// run resolves args[0] to a known industry profile via
// webgwefficacy's own IndustryProfileNames/BuildIndustryProfile --
// the single source of truth also used by the HTTP handler and
// report renderer, so this CLI never maintains its own, potentially
// drifting copy of the profile-name list -- and writes its Describe()
// and PrioritySummary(report) output to stdout. report is passed in
// rather than fetched here so this function stays testable against a
// synthetic CoverageReport as well as the real
// AudspectWebGWCoverageReport.
func run(args []string, report webgwefficacy.CoverageReport, stdout io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: webgwprofile <profile-name>\nknown profiles: %s", strings.Join(webgwefficacy.IndustryProfileNames(), ", "))
	}
	profile, ok, err := webgwefficacy.BuildIndustryProfile(args[0])
	if !ok {
		return fmt.Errorf("unknown profile %q -- known profiles: %s", args[0], strings.Join(webgwefficacy.IndustryProfileNames(), ", "))
	}
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
