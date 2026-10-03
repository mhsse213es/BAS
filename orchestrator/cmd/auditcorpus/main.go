package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/scenario/corpusaudit"
)

const (
	generatedPath = "internal/scenario/execclass_generated.go"
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
		log.Printf("WARNING: %v (both items excluded from the catalog, will surface as unresolved)", c)
	}

	reviewed, err := corpusaudit.LoadReviewedDecisions(reviewedPath)
	if err != nil {
		log.Fatalf("load %s: %v", reviewedPath, err)
	}

	classified := corpusaudit.Triage(keyed, reviewed)

	genFile, err := os.Create(generatedPath)
	if err != nil {
		log.Fatalf("create %s: %v", generatedPath, err)
	}
	defer genFile.Close()
	if err := corpusaudit.WriteGeneratedGo(genFile, classified); err != nil {
		log.Fatalf("write %s: %v", generatedPath, err)
	}

	if err := os.MkdirAll("internal/scenario/testdata", 0o755); err != nil {
		log.Fatalf("mkdir testdata: %v", err)
	}
	reportFile, err := os.Create(reportPath)
	if err != nil {
		log.Fatalf("create %s: %v", reportPath, err)
	}
	defer reportFile.Close()
	report := corpusaudit.BuildReport(classified)
	if err := corpusaudit.WriteReportMarkdown(reportFile, report); err != nil {
		log.Fatalf("write %s: %v", reportPath, err)
	}

	fmt.Printf("ART atomics loaded: %d\nART: %+v\nCaldera: %+v\n", artCount, report.ART, report.Caldera)
}
