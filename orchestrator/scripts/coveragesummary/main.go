package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"golang.org/x/tools/cover"
)

func main() {
	profilePath := flag.String("profile", "coverage.out", "path to a go test -coverprofile output file")
	flag.Parse()

	profiles, err := cover.ParseProfiles(*profilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "coveragesummary: parse %s: %v\n", *profilePath, err)
		os.Exit(1)
	}

	PrintSummary(os.Stdout, Summarize(profiles))
}

// PackageCoverage holds aggregated statement coverage for one Go package.
type PackageCoverage struct {
	Package string
	Covered int
	Total   int
}

// Percent returns covered/total as a percentage, 0 if Total is 0.
func (p PackageCoverage) Percent() float64 {
	if p.Total == 0 {
		return 0
	}
	return float64(p.Covered) / float64(p.Total) * 100
}

// Summarize aggregates per-file profile blocks into per-package totals,
// weighted by statement count (matching go tool cover's own methodology).
func Summarize(profiles []*cover.Profile) []PackageCoverage {
	totals := map[string]*PackageCoverage{}
	for _, p := range profiles {
		pkg := path.Dir(p.FileName)
		pc, ok := totals[pkg]
		if !ok {
			pc = &PackageCoverage{Package: pkg}
			totals[pkg] = pc
		}
		for _, b := range p.Blocks {
			pc.Total += b.NumStmt
			if b.Count > 0 {
				pc.Covered += b.NumStmt
			}
		}
	}

	result := make([]PackageCoverage, 0, len(totals))
	for _, pc := range totals {
		result = append(result, *pc)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Package < result[j].Package })
	return result
}

// PrintSummary writes an aligned "pkg ... NN.N%" table to w.
func PrintSummary(w io.Writer, summary []PackageCoverage) {
	maxLen := 0
	for _, pc := range summary {
		if len(pc.Package) > maxLen {
			maxLen = len(pc.Package)
		}
	}
	for _, pc := range summary {
		dots := strings.Repeat(".", maxLen-len(pc.Package)+3)
		fmt.Fprintf(w, "%s %s %.1f%%\n", pc.Package, dots, pc.Percent())
	}
}
