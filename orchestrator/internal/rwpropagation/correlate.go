package rwpropagation

import (
	"sort"

	"github.com/audspect/bas/internal/admatrix"
	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/latmove"
)

// TaggedADReachability tags one admatrix.Simulate result with the
// AssessmentID the caller claims it belongs to.
type TaggedADReachability struct {
	AssessmentID string
	Result       admatrix.SimResult
}

// TaggedLateralMovementAccess tags one latmove discovery result.
type TaggedLateralMovementAccess struct {
	AssessmentID string
	Technique    latmove.Technique
	Principal    string
	Destination  string
	Condition    latmove.AccessCondition
}

// TaggedLateralMovementExecution tags one latmove attempt outcome.
type TaggedLateralMovementExecution struct {
	AssessmentID string
	Key          latmove.AttemptKey
	Result       latmove.AttemptResult
}

// Input is everything the caller supplies for one assessment.
// RansomwareRows' correlation to Context.RunID is enforced by
// construction, not by a field on the row: the caller is expected to
// have fetched these via db.RWCapabilityAttempts(ctx, pool,
// Context.RunID), which already filtered by run_id -- there is no
// separate RunID field on db.RWAttemptRow to check here.
type Input struct {
	Context                  AssessmentContext
	ADReachability            []TaggedADReachability
	LateralMovementAccess     []TaggedLateralMovementAccess
	LateralMovementExecution  []TaggedLateralMovementExecution
	RansomwareRows            []db.RWAttemptRow
}

// Exclusion records one supplied item this package declined to include
// in the report, and why -- never dropped silently.
type Exclusion struct {
	Source string // "ad_reachability" | "lateral_movement_access" | "lateral_movement_execution"
	Reason string
}

// CorrelationStatus says whether every supplied item could be verified
// as pertaining to Context.AssessmentID.
type CorrelationStatus string

const (
	CorrelationEstablished  CorrelationStatus = "established"
	CorrelationUncorrelated CorrelationStatus = "uncorrelated"
)

// Report is the full cross-module propagation assessment for one
// AssessmentContext.
type Report struct {
	Assessment  AssessmentContext
	Correlation CorrelationStatus
	Exclusions  []Exclusion

	ADReachability            []ADReachability
	LateralMovementAccess     []LateralMovementAccess
	LateralMovementExecution  []LateralMovementExecution
	Containment               []LegContainment
	TimeToIsolate             TimeToIsolateStatus
	TimeToIsolateReason       string
}

const timeToIsolateReason = "no causal link between a detection event and an isolation action exists in this codebase today"

// BuildReport joins input's three evidence sources into one Report for
// input.Context. Never returns an error -- every "something was off"
// case is a value in the result.
func BuildReport(input Input) Report {
	report := Report{Assessment: input.Context}

	emptyContext := input.Context.AssessmentID == ""

	for _, item := range input.ADReachability {
		if emptyContext || item.AssessmentID != input.Context.AssessmentID {
			report.Exclusions = append(report.Exclusions, Exclusion{
				Source: "ad_reachability",
				Reason: exclusionReason(emptyContext, item.AssessmentID, input.Context.AssessmentID),
			})
			continue
		}
		report.ADReachability = append(report.ADReachability, ADReachability{
			Target:    item.Result.Target,
			Reachable: item.Result.Reachable,
			Steps:     item.Result.Steps,
			Level:     item.Result.Level,
		})
	}

	for _, item := range input.LateralMovementAccess {
		if emptyContext || item.AssessmentID != input.Context.AssessmentID {
			report.Exclusions = append(report.Exclusions, Exclusion{
				Source: "lateral_movement_access",
				Reason: exclusionReason(emptyContext, item.AssessmentID, input.Context.AssessmentID),
			})
			continue
		}
		report.LateralMovementAccess = append(report.LateralMovementAccess, LateralMovementAccess{
			Technique:   item.Technique,
			Principal:   item.Principal,
			Destination: item.Destination,
			Condition:   item.Condition,
		})
	}

	for _, item := range input.LateralMovementExecution {
		if emptyContext || item.AssessmentID != input.Context.AssessmentID {
			report.Exclusions = append(report.Exclusions, Exclusion{
				Source: "lateral_movement_execution",
				Reason: exclusionReason(emptyContext, item.AssessmentID, input.Context.AssessmentID),
			})
			continue
		}
		report.LateralMovementExecution = append(report.LateralMovementExecution, LateralMovementExecution{
			Key:    item.Key,
			Result: item.Result,
		})
	}

	if len(report.Exclusions) > 0 {
		report.Correlation = CorrelationUncorrelated
	} else {
		report.Correlation = CorrelationEstablished
	}

	report.Containment = []LegContainment{
		{Leg: "ad", Availability: ContainmentNoObserver},
		{Leg: "lateral_movement", Availability: ContainmentNoObserver},
		ransomwarePayloadContainment(input.RansomwareRows),
	}

	report.TimeToIsolate = TimeToIsolateNotEstablishable
	report.TimeToIsolateReason = timeToIsolateReason

	return report
}

func exclusionReason(emptyContext bool, suppliedID, contextID string) string {
	if emptyContext {
		return "no AssessmentID set on context"
	}
	return "AssessmentID mismatch: supplied " + suppliedID + ", context wants " + contextID
}

// ransomwarePayloadContainment derives the "ransomware_payload" leg from
// every distinct TechniqueID appearing anywhere in rows (any capability
// -- "attempted in this run"), sorted lexicographically for stable
// output order.
func ransomwarePayloadContainment(rows []db.RWAttemptRow) LegContainment {
	techniques := make(map[string]bool)
	for _, r := range rows {
		techniques[r.TechniqueID] = true
	}
	if len(techniques) == 0 {
		return LegContainment{Leg: "ransomware_payload", Availability: ContainmentNoObserver}
	}

	ids := make([]string, 0, len(techniques))
	for id := range techniques {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	entries := make([]RansomwareContainment, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, containmentEntryFor(id, rows))
	}
	return LegContainment{Leg: "ransomware_payload", Availability: ContainmentMeasured, Containment: entries}
}

// containmentEntryFor builds one technique's RansomwareContainment entry.
// Zero containment rows -> not_instrumented. Otherwise the earliest row
// wins (ties broken by lexicographically-smallest Action, deterministic
// regardless of input order), and its Verdict/SkipReason decide
// not_applicable vs evaluated.
func containmentEntryFor(techniqueID string, rows []db.RWAttemptRow) RansomwareContainment {
	var containmentRows []db.RWAttemptRow
	for _, r := range rows {
		if r.TechniqueID == techniqueID && r.Capability == "containment" {
			containmentRows = append(containmentRows, r)
		}
	}
	if len(containmentRows) == 0 {
		return RansomwareContainment{TechniqueID: techniqueID, Status: ContainmentStatusNotInstrumented}
	}

	sort.Slice(containmentRows, func(i, j int) bool {
		a, b := containmentRows[i], containmentRows[j]
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return a.Action < b.Action
	})
	r := containmentRows[0]

	status := ContainmentStatusEvaluated
	if r.Verdict == controlval.VerdictSkipped && r.SkipReason == controlval.SkipNotApplicable {
		status = ContainmentStatusNotApplicable
	}
	return RansomwareContainment{
		TechniqueID: techniqueID,
		Status:      status,
		Verdict:     r.Verdict,
		Reason:      r.Reason,
		CreatedAt:   r.CreatedAt,
	}
}
