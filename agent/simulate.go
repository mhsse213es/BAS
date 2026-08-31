package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"audspect/agent/protocol"
	"audspect/agent/sched"
)

// SimCategory is a group of related ATT&CK-aligned checks.
type SimCategory struct {
	Phase  string     `json:"phase"`
	Checks []SimCheck `json:"checks"`
}

// SimCheck is a single simulation result — matches orchestrator SimulationResult schema.
type SimCheck struct {
	ID           string                          `json:"id"`
	Technique    Tech                            `json:"technique"`
	Result       string                          `json:"result"`   // pass | fail | skipped
	Severity     string                          `json:"severity"` // Critical | High | Medium | Low
	ThreatImpact string                          `json:"threatImpact"`
	Details      string                          `json:"details"`
	Remediation  string                          `json:"remediation"`
	RawOutput    string                          `json:"rawOutput,omitempty"`
	DurationMs   int64                           `json:"durationMs"`
	ExecutedAt   time.Time                       `json:"executedAt"`
	Framework    string                          `json:"framework"`
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
// When selected is nil/empty, every check is run and all are kept. onCheck, if
// non-nil, is invoked once per executed check (Result already filled in) --
// runLocalScan uses this to emit live progress events, since these checks run
// synchronously with no other per-check hook available.
//
// gate.Wait(ctx) is called before each check, not mid-check: a check is a
// single fast synchronous read (registry/WMI/config), so there's no
// meaningful "partway through" point to pause at -- gating between checks
// mirrors runScenario's between-step granularity for ART/Custom steps. A
// nil gate is a no-op (see sched.Gate.Wait), so callers that don't need
// pause support (tests) can pass nil.
//
// ctx is checked both before and after gate.Wait -- mirrors sched.Run's
// runJob dispatch loop exactly, for the same reason: a cancel can race with
// a pause (fire while already blocked in Wait), so the post-Wait check
// catches a cancel that arrived while paused, not just one that arrived
// between checks. partial reports whether ctx was cancelled before every
// selected check ran; whatever ran before that is still returned in out.
func runChecks(ctx context.Context, cats []SimCategory, selected map[string]bool, gate *sched.Gate, onCheck func(SimCheck)) (out []SimCategory, partial bool) {
	out = make([]SimCategory, 0, len(cats))
	for _, cat := range cats {
		kept := make([]SimCheck, 0, len(cat.Checks))
		for i := range cat.Checks {
			if len(selected) > 0 && !selected[cat.Checks[i].ID] {
				continue
			}
			if ctx.Err() != nil {
				partial = true
				break
			}
			gate.Wait(ctx)
			if ctx.Err() != nil {
				partial = true
				break
			}
			cat.Checks[i].run()
			if onCheck != nil {
				onCheck(cat.Checks[i])
			}
			kept = append(kept, cat.Checks[i])
		}
		if len(kept) > 0 {
			out = append(out, SimCategory{Phase: cat.Phase, Checks: kept})
		}
		if partial {
			break
		}
	}
	return out, partial
}

// postureCatalogDefaultKey is the fallback catalog entry for any scenario ID
// not in knownPostureScenarios() -- e.g. a user-created custom Local Check
// scenario. RunScenarioChecks() already falls back to RunAllChecks() for an
// unrecognized ID at execution time; without this key the catalog side had
// no equivalent, so the orchestrator's "Customize" picker (and any live
// check-count summary) had nothing to show for a custom scenario even
// though it genuinely runs all checks fine. Must match the constant of the
// same name/value the orchestrator falls back to in GetPostureCatalog.
const postureCatalogDefaultKey = "*"

func checksToMeta(cats []SimCategory) []protocol.PostureCheckMeta {
	var metas []protocol.PostureCheckMeta
	for _, cat := range cats {
		for _, c := range cat.Checks {
			metas = append(metas, protocol.PostureCheckMeta{
				ID: c.ID, Phase: cat.Phase, TechniqueID: c.Technique.ID,
				Name: c.Technique.Name, Severity: c.Severity,
			})
		}
	}
	return metas
}

// BuildPostureCatalog harvests selectable-check metadata for every known posture
// scenario WITHOUT executing any check (checks are deferred since Part A), plus
// a postureCatalogDefaultKey entry for RunAllChecks() -- the set any unrecognized
// scenario ID actually runs.
func BuildPostureCatalog() map[string][]protocol.PostureCheckMeta {
	out := make(map[string][]protocol.PostureCheckMeta)
	for _, sid := range knownPostureScenarios() {
		if metas := checksToMeta(RunScenarioChecks(sid)); len(metas) > 0 {
			out[sid] = metas
		}
	}
	if metas := checksToMeta(RunAllChecks()); len(metas) > 0 {
		out[postureCatalogDefaultKey] = metas
	}
	return out
}
