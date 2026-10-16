// Command av-scenario-builder generates scenarios/av-ngav-assessment.yaml
// from internal/avscenario's real, already-tested
// AudspectAVAssessmentScenario() -- the step that turns that in-memory
// scenario.Scenario into the actual YAML file the agent-dispatch engine
// loads from disk at startup. Re-run this whenever avcatalog's
// dispatchable seed vectors change, then re-sign the output:
//
//	go run ./scripts/av-scenario-builder
//	go run scripts/signer.go sign private_key.pem scenarios/av-ngav-assessment.yaml
package main

import (
	"fmt"
	"os"

	"github.com/audspect/bas/internal/avscenario"
	"gopkg.in/yaml.v3"
)

// outputPath is relative to the orchestrator Go module root (where this is
// run via `go run ./scripts/av-scenario-builder`) -- scenarios/ lives one
// level up, at the repo root, alongside orchestrator/.
const outputPath = "../scenarios/av-ngav-assessment.yaml"

func main() {
	s, err := avscenario.AudspectAVAssessmentScenario()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build scenario: %v\n", err)
		os.Exit(1)
	}
	s.Author = "Audspect Research"
	s.Tags = []string{"av-ngav-mastery", "antivirus", "ngav", "endpoint-protection"}
	s.MITREPhases = []string{"execution", "defense-evasion", "persistence"}
	s.Description = "Antivirus and next-gen AV assessment: concretely dispatchable file-based, " +
		"script/fileless, behavioral, network-delivered, persistence, and false-positive-resilience " +
		"vectors from internal/avcatalog's seed catalog. Every step is a harmless, disposable, " +
		"purpose-built simulation with its own cleanup -- never a real attack payload."

	b, err := yaml.Marshal(&s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outputPath, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", outputPath, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d steps)\n", outputPath, len(s.Steps))
}
