package reporting

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

func step(id, tactic, verdict string, at time.Time) models.SimulationResult {
	return models.SimulationResult{
		Technique:  models.AttackTechnique{ID: id, Name: id + " name", Tactic: tactic},
		Result:     models.CheckResult(verdict),
		ExecutedAt: at,
	}
}

func TestClassifyOutcome(t *testing.T) {
	dets := []DetectionTechnique{{TechniqueID: "T1003", Verdict: "detected", Confidence: "high"}}
	detByTech := detTechIndex(dets)

	cases := []struct {
		name string
		r    models.SimulationResult
		want string
	}{
		{"blocked pass", models.SimulationResult{Result: models.ResultPass, Technique: models.AttackTechnique{ID: "T1059"}}, "blocked"},
		{"blocked result", models.SimulationResult{Result: models.ResultBlocked, Technique: models.AttackTechnique{ID: "T1059"}}, "blocked"},
		{"error excluded", models.SimulationResult{Result: models.ResultError, Technique: models.AttackTechnique{ID: "T1059"}}, "excluded"},
		{"skipped excluded", models.SimulationResult{Result: models.ResultSkipped, Technique: models.AttackTechnique{ID: "T1059"}}, "excluded"},
		{"fail with detection alert", models.SimulationResult{Result: models.ResultFail, Technique: models.AttackTechnique{ID: "T1003"}}, "detected"},
		{"fail no detection", models.SimulationResult{Result: models.ResultFail, Technique: models.AttackTechnique{ID: "T1059"}}, "missed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyOutcome(c.r, detByTech); got != c.want {
				t.Errorf("classifyOutcome() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestBuildKillChain(t *testing.T) {
	base := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	results := []models.SimulationResult{
		step("T1486", "impact", "blocked", base.Add(4*time.Minute)),
		step("T1566", "initial-access", "pass", base),
		step("T1059.001", "execution", "fail", base.Add(time.Minute)),
		step("T1003.001", "credential-access", "fail", base.Add(2*time.Minute)),
		step("T1018", "discovery", "error", base.Add(3*time.Minute)), // excluded
	}
	dets := []DetectionTechnique{
		{TechniqueID: "T1059.001", Verdict: "detected", Confidence: "high", TimeToDetectMs: 4000},
		{TechniqueID: "T1003.001", Verdict: "undetected"},
	}
	kc := buildKillChain(results, dets)

	// ERROR excluded; remaining ordered by kill-chain phase.
	wantOrder := []struct{ id, outcome string }{
		{"T1566", "prevented"},    // initial-access
		{"T1059.001", "detected"}, // execution
		{"T1003.001", "missed"},   // credential-access (undetected)
		{"T1486", "prevented"},    // impact
	}
	if len(kc) != len(wantOrder) {
		t.Fatalf("got %d steps, want %d: %+v", len(kc), len(wantOrder), kc)
	}
	for i, w := range wantOrder {
		if kc[i].TechniqueID != w.id || kc[i].Outcome != w.outcome {
			t.Fatalf("step %d = %s/%s, want %s/%s", i, kc[i].TechniqueID, kc[i].Outcome, w.id, w.outcome)
		}
	}
	if kc[1].Confidence != "high" || kc[1].LatencyMs != 4000 {
		t.Fatalf("detected step missing confidence/latency: %+v", kc[1])
	}
}
