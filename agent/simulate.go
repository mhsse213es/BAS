package main

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// SimCategory is a group of related ATT&CK-aligned checks.
type SimCategory struct {
	Phase  string     `json:"phase"`
	Checks []SimCheck `json:"checks"`
}

// SimCheck is a single simulation result — matches orchestrator SimulationResult schema.
type SimCheck struct {
	ID           string    `json:"id"`
	Technique    Tech      `json:"technique"`
	Result       string    `json:"result"`   // pass | fail | skipped
	Severity     string    `json:"severity"` // Critical | High | Medium | Low
	ThreatImpact string    `json:"threatImpact"`
	Details      string    `json:"details"`
	Remediation  string    `json:"remediation"`
	RawOutput    string    `json:"rawOutput,omitempty"`
	DurationMs   int64     `json:"durationMs"`
	ExecutedAt   time.Time `json:"executedAt"`
	Framework    string    `json:"framework"`
	fn           func() (result, details string) // deferred execution; never serialized
}

// Tech is a MITRE ATT&CK technique reference.
type Tech struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
}

func checkID(techID, name string) string {
	h := sha256.Sum256([]byte(techID + "|" + name))
	return hex.EncodeToString(h[:])[:8]
}

func check(techID, name, tactic, severity, threat, fix string,
	fn func() (result, details string)) SimCheck {

	return SimCheck{
		ID:           checkID(techID, name),
		Technique:    Tech{ID: techID, Name: name, Tactic: tactic},
		Severity:     severity,
		ThreatImpact: threat,
		Remediation:  fix,
		Framework:    "custom",
		fn:           fn,
	}
}

// run executes the deferred check, filling result fields. No-op if already run
// or if fn is nil (defensive).
func (c *SimCheck) run() {
	if c.fn == nil {
		return
	}
	start := time.Now()
	c.Result, c.Details = c.fn()
	c.DurationMs = time.Since(start).Milliseconds()
	c.ExecutedAt = time.Now()
}

// runChecks executes the checks in cats. When selected is non-empty, only checks
// whose ID is in selected are run AND kept; categories left empty are dropped.
// When selected is nil/empty, every check is run and all are kept.
func runChecks(cats []SimCategory, selected map[string]bool) []SimCategory {
	out := make([]SimCategory, 0, len(cats))
	for _, cat := range cats {
		kept := make([]SimCheck, 0, len(cat.Checks))
		for i := range cat.Checks {
			if len(selected) > 0 && !selected[cat.Checks[i].ID] {
				continue
			}
			cat.Checks[i].run()
			kept = append(kept, cat.Checks[i])
		}
		if len(kept) > 0 {
			out = append(out, SimCategory{Phase: cat.Phase, Checks: kept})
		}
	}
	return out
}

// BuildPostureCatalog harvests selectable-check metadata for every known posture
// scenario WITHOUT executing any check (checks are deferred since Part A).
func BuildPostureCatalog() map[string][]PostureCheckMeta {
	out := make(map[string][]PostureCheckMeta)
	for _, sid := range knownPostureScenarios() {
		var metas []PostureCheckMeta
		for _, cat := range RunScenarioChecks(sid) {
			for _, c := range cat.Checks {
				metas = append(metas, PostureCheckMeta{
					ID: c.ID, Phase: cat.Phase, TechniqueID: c.Technique.ID,
					Name: c.Technique.Name, Severity: c.Severity,
				})
			}
		}
		if len(metas) > 0 {
			out[sid] = metas
		}
	}
	return out
}
