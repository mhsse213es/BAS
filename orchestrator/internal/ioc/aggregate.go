package ioc

import (
	"slices"
	"time"

	"github.com/audspect/bas/internal/scenario"
)

// RunIndicator is one distinct indicator found anywhere in a run, aggregated
// across every step/technique that produced it. Reused as both the in-memory
// aggregation result and the DB/API shape (internal/db and internal/api
// consume this directly -- no duplicate struct).
type RunIndicator struct {
	Type          string     `json:"type"`
	Value         string     `json:"value"`
	Algorithm     string     `json:"hashAlgorithm,omitempty"`
	Confidence    int        `json:"confidence"`
	Source        string     `json:"source"` // stdout | stderr | details (first occurrence)
	OffsetStart   int        `json:"offsetStart"`
	OffsetEnd     int        `json:"offsetEnd"`
	TechniqueIDs  []string   `json:"techniqueIds"`
	SimulationIDs []string   `json:"simulationIds"`
	ExtractedAt   *time.Time `json:"extractedAt,omitempty"` // set on DB read; nil on fresh extraction (omitempty has no effect on a non-pointer time.Time)
}

type dedupKey struct {
	typ   string
	value string
}

// BuildRunIndicators walks every step's raw text in a fixed, deterministic
// order -- execResults in slice order (Stdout then Stderr for each), then
// checks in slice order (Details) -- and dedups matches into one
// RunIndicator per distinct (type, value) pair for the whole run.
// "First occurrence" for Source/OffsetStart/OffsetEnd means first in this
// walk order, not first by wall-clock time.
func BuildRunIndicators(
	execResults []scenario.ExecResult,
	checks []scenario.SimCheckResult,
	stepMap map[string]scenario.Step,
) []RunIndicator {
	byKey := make(map[dedupKey]*RunIndicator)
	var order []dedupKey

	add := func(ind Indicator, source, techniqueID, simulationID string) {
		key := dedupKey{typ: ind.Type, value: ind.Value}
		existing, found := byKey[key]
		if !found {
			existing = &RunIndicator{
				Type: ind.Type, Value: ind.Value, Algorithm: ind.Algorithm,
				Confidence: ind.Confidence, Source: source,
				OffsetStart: ind.OffsetStart, OffsetEnd: ind.OffsetEnd,
			}
			byKey[key] = existing
			order = append(order, key)
		}
		if techniqueID != "" && !slices.Contains(existing.TechniqueIDs, techniqueID) {
			existing.TechniqueIDs = append(existing.TechniqueIDs, techniqueID)
		}
		if simulationID != "" && !slices.Contains(existing.SimulationIDs, simulationID) {
			existing.SimulationIDs = append(existing.SimulationIDs, simulationID)
		}
	}

	for _, er := range execResults {
		techniqueID := stepMap[er.TaskID].TechniqueID
		for _, ind := range ExtractIndicators(er.Stdout) {
			add(ind, "stdout", techniqueID, er.TaskID)
		}
		for _, ind := range ExtractIndicators(er.Stderr) {
			add(ind, "stderr", techniqueID, er.TaskID)
		}
	}
	for _, ch := range checks {
		for _, ind := range ExtractIndicators(ch.Details) {
			add(ind, "details", ch.TechniqueID, ch.ID)
		}
	}

	out := make([]RunIndicator, 0, len(order))
	for _, key := range order {
		out = append(out, *byKey[key])
	}
	return out
}
