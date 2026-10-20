package verifysync

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/dlpreport"
	"github.com/audspect/bas/internal/reporting"
)

// DLPRecordEntry is one persisted DLP evaluation: a dlpreport.Record plus the
// verbatim comparison that produced it. The comparison is kept beside the
// Record, not folded into a Record dimension, so Match, Mismatch and
// MissingEvidence stay distinct without bending Classification to carry them.
type DLPRecordEntry struct {
	TaskID          string           `json:"taskId"`
	ExpectationID   string           `json:"expectationId"`
	TechniqueID     string           `json:"techniqueId"`
	ExpectedOutcome string           `json:"expectedOutcome"`
	ObservedOutcome string           `json:"observedOutcome"`
	Comparison      string           `json:"comparison"`
	Status          string           `json:"status"`
	Record          dlpreport.Record `json:"record"`
	// TestEventStart and TestEventSource are stored in their own nullable
	// columns, not in the record JSON (json:"-"), so the record shape is
	// unchanged. Both are nil when no usable payload marker exists.
	TestEventStart  *time.Time `json:"-"`
	TestEventSource *string    `json:"-"`
}

const dlpRecordSourceSystem = "dlp-verifier"

// dlpEntriesFromVerdicts derives one entry per DLP verdict. Non-DLP verdicts
// (DLPEvidence == nil) produce nothing, so every other family's output is
// unchanged. Every DLP verdict produces an entry, including skips and
// unobserved steps: those are the honest "not evaluated" distinction.
func dlpEntriesFromVerdicts(scenarioID string, verdicts []reporting.VerificationResult) []DLPRecordEntry {
	var out []DLPRecordEntry
	for _, vr := range verdicts {
		if vr.DLPEvidence == nil {
			continue
		}
		out = append(out, dlpEntryFromVerdict(scenarioID, vr))
	}
	return out
}

func dlpEntryFromVerdict(scenarioID string, vr reporting.VerificationResult) DLPRecordEntry {
	ev := vr.DLPEvidence
	enforcement, enfNote := deriveDLPEnforcement(vr.ObservedOutcome, ev)

	limits := []string{}
	if ev.Limitations != "" {
		limits = append(limits, ev.Limitations)
	}
	if enfNote != "" {
		limits = append(limits, enfNote)
	}
	limits = append(limits,
		"Classification not evaluated: a policy-outcome comparison is not a classification-accuracy measurement.",
		"No SIEM or ticket correlation in this path: telemetry and response were not evaluated.",
		"Collection time is not recorded; the verdict time is not evidence time, so no timestamp is claimed.",
		"First evaluation wins; a sink receipt that arrives after this evaluation is not reflected in this record.",
	)

	return DLPRecordEntry{
		TaskID:          vr.TaskID,
		ExpectationID:   vr.ExpectedID,
		TechniqueID:     vr.TechniqueID,
		ExpectedOutcome: vr.ExpectedOutcome,
		ObservedOutcome: vr.ObservedOutcome,
		Comparison:      string(vr.Comparison),
		Status:          vr.Status,
		// ActionAttempted and Confidence stay empty: vr.Finding.Title is the
		// gap-finding text, not the action, and vr.Confidence is the author's
		// declared confidence, not confidence in the observation.
		// Timestamp stays zero: vr.Timestamp is verification time, not
		// collection time (see the limitation above).
		Record: dlpreport.Record{
			ScenarioID:     scenarioID,
			Enforcement:    enforcement,
			Classification: dlpreport.ClassificationNotEvaluated,
			Telemetry:      dlpreport.TelemetryUnverifiable,
			Response:       dlpreport.ResponseNotTested,
			Provenance: dlpreport.EvidenceProvenance{
				SourceSystem:     dlpRecordSourceSystem,
				CorrelationID:    ev.CorrelationID,
				CollectionMethod: ev.CollectionMethod,
			},
			Limitations: strings.Join(limits, " "),
		},
		TestEventStart:  testEventStartOf(ev),
		TestEventSource: testEventSourceOf(ev),
	}
}

// testEventStartOf returns the payload-recorded test-event start, or nil when
// the step produced no usable marker. A zero time is never stored: it would
// read back as a real timestamp.
func testEventStartOf(ev *reporting.DLPEvidence) *time.Time {
	if ev.TestEventStart.IsZero() {
		return nil
	}
	at := ev.TestEventStart
	return &at
}

// testEventSourceOf names how the start was obtained. It is set exactly when a
// start time is set, so a stored timestamp always has a source.
func testEventSourceOf(ev *reporting.DLPEvidence) *string {
	if ev.TestEventStart.IsZero() {
		return nil
	}
	src := "payload-marker"
	return &src
}

// deriveDLPEnforcement maps the observed evidence onto the Enforcement
// vocabulary, in precedence order. Overridden comes first: an override means
// the policy outcome was bypassed, whatever the step then observed.
// Allowed requires destination-side proof (sink-receipt); a self-reported
// success is never promoted to Allowed.
func deriveDLPEnforcement(observed string, ev *reporting.DLPEvidence) (dlpreport.EnforcementOutcome, string) {
	if ev.Override != nil && ev.Override.Occurred {
		return dlpreport.EnforcementOverridden, "Overridden: an operator override was observed for this step."
	}
	switch observed {
	case reporting.ObservationBlocked:
		if ev.CollectionMethod == "sink-receipt" {
			// Absence of a receipt for an issued token is not proof of a block:
			// a lost or late receipt looks identical. Never record it as Blocked.
			return dlpreport.EnforcementUnknown, "No destination receipt was observed for this step's sink token; absence is not proof of a block, since a lost or late receipt looks the same."
		}
		return dlpreport.EnforcementBlocked, "Blocked is self-reported by the step's DLP_OBSERVATION marker; the destination did not confirm it."
	case reporting.ObservationSucceeded:
		if ev.CollectionMethod == "sink-receipt" {
			return dlpreport.EnforcementAllowed, ""
		}
		return dlpreport.EnforcementUnknown, "Success is self-reported by the step marker, not confirmed at the destination; enforcement is recorded as Unknown, not Allowed."
	default:
		return dlpreport.EnforcementUnknown, "No enforcement observation was collected for this step."
	}
}

// persistDLPRecords inserts entries idempotently. The primary key is
// (run_id, expectation_id) and the insert does nothing on conflict, so a retried
// processRun re-inserts only rows it has not written yet.
func persistDLPRecords(ctx context.Context, db *pgxpool.Pool, runID string, entries []DLPRecordEntry) error {
	for _, e := range entries {
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := db.Exec(ctx,
			`INSERT INTO dlp_evidence_records (run_id, task_id, expectation_id, technique_id, scenario_id, record, created_at, test_event_timestamp, test_event_source)
			 VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, $8)
			 ON CONFLICT (run_id, task_id, expectation_id) DO NOTHING`,
			runID, e.TaskID, e.ExpectationID, e.TechniqueID, e.Record.ScenarioID, string(raw),
			e.TestEventStart, e.TestEventSource,
		); err != nil {
			return err
		}
	}
	return nil
}

// DLPRecordsForRun reads back the entries persisted for a run, ordered by
// expectation ID. It is the read side of persistDLPRecords: nothing else
// derives records, and a missing run returns an empty slice, not an error.
func DLPRecordsForRun(ctx context.Context, db *pgxpool.Pool, runID string) ([]DLPRecordEntry, error) {
	rows, err := db.Query(ctx,
		`SELECT record FROM dlp_evidence_records WHERE run_id = $1 ORDER BY task_id, expectation_id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DLPRecordEntry{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var e DLPRecordEntry
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
