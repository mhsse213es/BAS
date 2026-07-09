package main

import (
	"bytes"
	"testing"

	"golang.org/x/tools/cover"
)

func TestSummarize_AggregatesPerPackage(t *testing.T) {
	profiles := []*cover.Profile{
		{
			FileName: "github.com/audspect/bas/internal/relationships/store.go",
			Blocks: []cover.ProfileBlock{
				{NumStmt: 10, Count: 10},
				{NumStmt: 5, Count: 0},
			},
		},
		{
			FileName: "github.com/audspect/bas/internal/relationships/handlers.go",
			Blocks: []cover.ProfileBlock{
				{NumStmt: 5, Count: 5},
			},
		},
		{
			FileName: "github.com/audspect/bas/internal/api/routes.go",
			Blocks: []cover.ProfileBlock{
				{NumStmt: 4, Count: 0},
			},
		},
	}

	got := Summarize(profiles)
	if len(got) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(got))
	}

	byPkg := map[string]PackageCoverage{}
	for _, pc := range got {
		byPkg[pc.Package] = pc
	}

	rel := byPkg["github.com/audspect/bas/internal/relationships"]
	if rel.Covered != 15 || rel.Total != 20 {
		t.Fatalf("relationships: covered=%d total=%d, want 15/20", rel.Covered, rel.Total)
	}

	api := byPkg["github.com/audspect/bas/internal/api"]
	if api.Covered != 0 || api.Total != 4 {
		t.Fatalf("api: covered=%d total=%d, want 0/4", api.Covered, api.Total)
	}
}

func TestPackageCoverage_Percent(t *testing.T) {
	pc := PackageCoverage{Covered: 15, Total: 20}
	if got := pc.Percent(); got != 75.0 {
		t.Fatalf("Percent() = %v, want 75.0", got)
	}
}

func TestPackageCoverage_Percent_ZeroTotal(t *testing.T) {
	pc := PackageCoverage{Covered: 0, Total: 0}
	if got := pc.Percent(); got != 0 {
		t.Fatalf("Percent() = %v, want 0", got)
	}
}

func TestPrintSummary_FormatsAlignedTable(t *testing.T) {
	var buf bytes.Buffer
	PrintSummary(&buf, []PackageCoverage{
		{Package: "api", Covered: 92, Total: 100},
		{Package: "verification", Covered: 98, Total: 100},
	})

	got := buf.String()
	if !bytes.Contains([]byte(got), []byte("92.0%")) {
		t.Fatalf("expected output to contain api coverage, got:\n%s", got)
	}
	if !bytes.Contains([]byte(got), []byte("98.0%")) {
		t.Fatalf("expected output to contain verification coverage, got:\n%s", got)
	}
}
