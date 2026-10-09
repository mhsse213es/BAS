package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/scenario/corpusaudit"
)

// writeFileAtomically writes write's output to a temp file in path's own
// directory, then renames it over path only on success -- so a mid-write
// failure (disk full, process killed) never leaves path truncated or
// partially overwritten. On any failure the temp file is removed and path
// is left exactly as it was before the call.
func writeFileAtomically(path string, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if err := write(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

const (
	generatedPath = "internal/scenario/execclass_generated.json"
	reviewedPath  = "internal/scenario/execclass_reviewed.yaml"
	reportPath    = "internal/scenario/testdata/execclass_corpus_report.md"
)

func main() {
	ctx := context.Background()
	dbURL := os.Getenv("DATABASE_URL")
	calderaURL := os.Getenv("CALDERA_URL")
	calderaKey := os.Getenv("CALDERA_API_KEY")
	if dbURL == "" || calderaURL == "" {
		log.Fatal("auditcorpus requires DATABASE_URL and CALDERA_URL -- run via the local compose stack: docker compose --profile audit run --rm auditcorpus")
	}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("connect to postgres: %v", err)
	}
	defer pool.Close()

	artStore, err := scenario.NewARTStoreFromDB(ctx, pool, nil)
	if err != nil {
		log.Fatalf("load ART atomics: %v", err)
	}

	var items []corpusaudit.DiscoveredItem
	for _, tech := range artStore.ListTechniques() {
		for _, step := range artStore.GetStepsByPlatform(tech, "windows") {
			items = append(items, corpusaudit.DiscoveredItem{
				Source:      "art",
				TechniqueID: step.TechniqueID,
				Name:        step.Name,
				Executor:    step.Executor,
				Command:     step.Command,
				Reachable:   step.Command != "" && step.TechniqueID != "",
			})
		}
	}
	if len(items) == 0 {
		log.Fatal("loaded zero ART atomics from art_atomic_tests -- is the table populated? (the orchestrator's own startup import populates it; confirm the compose stack's orchestrator service has started at least once)")
	}
	artCount := len(items)

	raw, err := scenario.FetchRawCalderaAbilities(calderaURL, calderaKey)
	if err != nil {
		log.Fatalf("fetch Caldera abilities: %v", err)
	}
	if len(raw) == 0 {
		log.Fatal("fetched zero Caldera abilities -- is Caldera still loading its ability library? check `docker compose ps caldera` reports healthy")
	}
	for _, ab := range raw {
		items = append(items, corpusaudit.DiscoveredItem{
			Source:      "caldera",
			TechniqueID: ab.TechniqueID,
			Name:        ab.Name,
			Executor:    ab.Executor,
			Command:     ab.Command,
			AbilityID:   ab.AbilityID,
			Reachable:   ab.Command != "" && ab.TechniqueID != "",
		})
	}

	keyed, collisions := corpusaudit.DeriveActionKeys(items)
	for _, c := range collisions {
		log.Printf("WARNING: %v (both items excluded from the catalog, see report.*.Collisions -- not folded into Unresolved)", c)
	}

	reviewed, err := corpusaudit.LoadReviewedDecisions(reviewedPath)
	if err != nil {
		log.Fatalf("load %s: %v", reviewedPath, err)
	}

	classified := corpusaudit.Triage(keyed, reviewed)

	if err := writeFileAtomically(generatedPath, func(w io.Writer) error {
		return corpusaudit.WriteGeneratedJSON(w, classified)
	}); err != nil {
		log.Fatalf("write %s: %v", generatedPath, err)
	}

	if err := os.MkdirAll("internal/scenario/testdata", 0o755); err != nil {
		log.Fatalf("mkdir testdata: %v", err)
	}
	report := corpusaudit.BuildReport(classified, collisions)
	if err := writeFileAtomically(reportPath, func(w io.Writer) error {
		return corpusaudit.WriteReportMarkdown(w, report)
	}); err != nil {
		log.Fatalf("write %s: %v", reportPath, err)
	}

	fmt.Printf("ART atomics loaded: %d\nART: %+v\nCaldera: %+v\n", artCount, report.ART, report.Caldera)
}
