package tcv

import (
	"context"
	"fmt"
	"time"
)

// Stage names one leg of the factory pipeline whose duration the SLA
// projection measures (spec §9).
type Stage string

const (
	StageQueue      Stage = "queue"      // threat_observed -> threat_eligible
	StageGeneration Stage = "generation" // threat_eligible -> first content_created
	StageValidation Stage = "validation" // first content_created -> first validated_coverage
	StageEndToEnd   Stage = "end_to_end" // threat_observed -> first validated_coverage
)

// stageSeconds computes the per-leg stage durations (whole seconds) from an
// in-memory event list, using the earliest event_time of each milestone
// (spec §9). A nil value means the stage is open: one of its bounding events
// has not occurred. It never returns zero for an open stage.
func stageSeconds(events []Event) map[Stage]*int64 {
	var observed, eligible, created, validated *time.Time
	earliest := func(dst **time.Time, t time.Time) {
		if *dst == nil || t.Before(**dst) {
			tt := t
			*dst = &tt
		}
	}
	for _, e := range events {
		switch e.Type {
		case EventThreatObserved:
			earliest(&observed, e.EventTime)
		case EventThreatEligible:
			earliest(&eligible, e.EventTime)
		case EventContentCreated:
			earliest(&created, e.EventTime)
		case EventValidatedCoverage:
			earliest(&validated, e.EventTime)
		}
	}
	delta := func(from, to *time.Time) *int64 {
		if from == nil || to == nil {
			return nil
		}
		s := int64(to.Sub(*from).Seconds())
		return &s
	}
	return map[Stage]*int64{
		StageQueue:      delta(observed, eligible),
		StageGeneration: delta(eligible, created),
		StageValidation: delta(created, validated),
		StageEndToEnd:   delta(observed, validated),
	}
}

// SLASegment is one (source, content_type, cohort) row of the report. For the
// validated cohort P50Seconds/P95Seconds are set (percentiles over that
// segment's legs for the requested stage); for failed/open they are nil and
// only N (the cohort count) is meaningful.
type SLASegment struct {
	Source      string   `json:"source"`
	ContentType string   `json:"content_type"` // relationship_kind: emulates | generated_for | "" (pre-leg)
	Cohort      string   `json:"cohort"`       // validated | failed | open
	N           int      `json:"n"`
	P50Seconds  *float64 `json:"p50_seconds,omitempty"`
	P95Seconds  *float64 `json:"p95_seconds,omitempty"`
}

// SLAReport is the internal factory-SLA projection for one stage and window
// (spec §9/§15). Percentiles are over the validated cohort only; the open
// cohort's count and oldest age defang censoring bias; Bottleneck names the
// stage with the largest validated P95 across all four stages.
type SLAReport struct {
	Stage             Stage        `json:"stage"`
	Segments          []SLASegment `json:"segments"`
	OpenCount         int          `json:"open_count"`
	OldestOpenSeconds *int64       `json:"oldest_open_seconds,omitempty"`
	Bottleneck        Stage        `json:"bottleneck"`
	IncompleteWindow  bool         `json:"incomplete_window"`
}

// legDurationsCTE builds one row per (threat, relationship_kind) leg with its
// four stage durations (seconds), terminal cohort, source, incompleteness and
// a window anchor. Threat-level events (observed/eligible) are shared across a
// threat's legs via join on threat_id; a threat with observed events but no
// content yet becomes a single pre-leg row (content_type ”). The content
// milestones join through content_version_threats, which is what carries the
// relationship_kind (the "content type" segment).
const legDurationsCTE = `
WITH obs AS (
	SELECT threat_id, min(event_time) AS t, min(payload->>'source') AS source
	FROM tcf_pipeline_events WHERE event_type='threat_observed' GROUP BY threat_id
),
elig AS (
	SELECT threat_id, min(event_time) AS t FROM tcf_pipeline_events WHERE event_type='threat_eligible' GROUP BY threat_id
),
cre AS (
	SELECT cvt.threat_id, cvt.relationship_kind AS kind, min(e.event_time) AS t
	FROM tcf_pipeline_events e JOIN content_version_threats cvt ON cvt.content_version_id = e.content_version_id
	WHERE e.event_type='content_created' GROUP BY 1,2
),
val AS (
	SELECT cvt.threat_id, cvt.relationship_kind AS kind, min(e.event_time) AS t
	FROM tcf_pipeline_events e JOIN content_version_threats cvt ON cvt.content_version_id = e.content_version_id
	WHERE e.event_type='validated_coverage' GROUP BY 1,2
),
fail AS (
	SELECT DISTINCT cvt.threat_id, cvt.relationship_kind AS kind
	FROM tcf_pipeline_events e JOIN content_version_threats cvt ON cvt.content_version_id = e.content_version_id
	WHERE e.event_type='validation_resulted' AND e.payload->>'outcome' IN ('FAIL','ERROR')
),
content_legs AS (
	SELECT threat_id, kind FROM cre UNION SELECT threat_id, kind FROM val
),
all_legs AS (
	SELECT threat_id, kind FROM content_legs
	UNION
	SELECT o.threat_id, ''::text FROM obs o
	WHERE NOT EXISTS (SELECT 1 FROM content_legs cl WHERE cl.threat_id = o.threat_id)
),
legdur AS (
	SELECT l.threat_id,
		l.kind AS content_type,
		COALESCE(obs.source,'unknown') AS source,
		CASE WHEN val.t IS NOT NULL THEN 'validated'
			 WHEN fail.threat_id IS NOT NULL THEN 'failed'
			 ELSE 'open' END AS cohort,
		-- Incomplete = a backfill gap: the leg has downstream content/coverage
		-- but the eligible that should precede it was never recorded. A threat
		-- merely still queuing (observed, no content yet) is open, not incomplete.
		((cre.t IS NOT NULL OR val.t IS NOT NULL) AND elig.t IS NULL) AS incomplete,
		-- Anomalous = an implausible ordering (a negative stage duration), e.g. a
		-- post-upgrade fabricated eligible stamped after a backfilled created.
		-- Such a leg's timings are untrustworthy and are kept out of percentiles.
		(COALESCE(EXTRACT(EPOCH FROM (elig.t - obs.t)), 0) < 0
		 OR COALESCE(EXTRACT(EPOCH FROM (cre.t - elig.t)), 0) < 0
		 OR COALESCE(EXTRACT(EPOCH FROM (val.t - cre.t)), 0) < 0
		 OR COALESCE(EXTRACT(EPOCH FROM (val.t - obs.t)), 0) < 0) AS anomalous,
		EXTRACT(EPOCH FROM (elig.t - obs.t))::double precision AS queue_sec,
		EXTRACT(EPOCH FROM (cre.t - elig.t))::double precision AS gen_sec,
		EXTRACT(EPOCH FROM (val.t - cre.t))::double precision AS val_sec,
		EXTRACT(EPOCH FROM (val.t - obs.t))::double precision AS e2e_sec,
		obs.t  AS observed_at,
		elig.t AS eligible_at,
		cre.t  AS created_at,
		COALESCE(obs.t, cre.t, val.t) AS anchor_at
	FROM all_legs l
	LEFT JOIN obs  ON obs.threat_id  = l.threat_id
	LEFT JOIN elig ON elig.threat_id = l.threat_id
	LEFT JOIN cre  ON cre.threat_id  = l.threat_id AND cre.kind = l.kind
	LEFT JOIN val  ON val.threat_id  = l.threat_id AND val.kind = l.kind
	LEFT JOIN fail ON fail.threat_id = l.threat_id AND fail.kind = l.kind
)`

func stageColumn(stage Stage) string {
	switch stage {
	case StageGeneration:
		return "gen_sec"
	case StageValidation:
		return "val_sec"
	case StageEndToEnd:
		return "e2e_sec"
	default:
		return "queue_sec"
	}
}

// startColumn is the presence of the stage's STARTING milestone -- a leg that
// has it entered the stage, whether or not it finished. Failed/open cohort
// counts use this (so a leg that failed or is still in the stage is visible,
// not hidden by survivor bias), while the validated percentile uses the full
// duration column.
func startColumn(stage Stage) string {
	switch stage {
	case StageGeneration:
		return "eligible_at"
	case StageValidation:
		return "created_at"
	default: // queue, end_to_end both start at threat_observed
		return "observed_at"
	}
}

// SLA is the internal factory-SLA projection for one stage and window
// (spec §9/§15). Percentiles are over the validated cohort of the stage's own
// population (legs with both of the stage's bounding events, not incomplete);
// failed/open legs in that population are reported as counts; the open cohort
// is reported stage-independently to defang censoring bias; Bottleneck names
// the component stage (queue/generation/validation, never end_to_end, which is
// their sum) with the largest validated P95.
func (s *Store) SLA(ctx context.Context, stage Stage, since time.Time) (SLAReport, error) {
	col := stageColumn(stage)
	startCol := startColumn(stage)
	rep := SLAReport{Stage: stage}

	vq := legDurationsCTE + `
		SELECT source, content_type, count(*) AS n,
			percentile_cont(0.5)  WITHIN GROUP (ORDER BY ` + col + `) AS p50,
			percentile_cont(0.95) WITHIN GROUP (ORDER BY ` + col + `) AS p95
		FROM legdur
		WHERE anchor_at >= $1 AND cohort='validated' AND NOT incomplete AND NOT anomalous AND ` + col + ` IS NOT NULL
		GROUP BY source, content_type`
	rows, err := s.pool.Query(ctx, vq, since)
	if err != nil {
		return rep, fmt.Errorf("tcv: sla validated: %w", err)
	}
	for rows.Next() {
		seg := SLASegment{Cohort: "validated"}
		if err := rows.Scan(&seg.Source, &seg.ContentType, &seg.N, &seg.P50Seconds, &seg.P95Seconds); err != nil {
			rows.Close()
			return rep, err
		}
		rep.Segments = append(rep.Segments, seg)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return rep, err
	}

	cq := legDurationsCTE + `
		SELECT source, content_type, cohort, count(*) AS n
		FROM legdur
		WHERE anchor_at >= $1 AND cohort IN ('failed','open') AND ` + startCol + ` IS NOT NULL
		GROUP BY source, content_type, cohort`
	rows2, err := s.pool.Query(ctx, cq, since)
	if err != nil {
		return rep, fmt.Errorf("tcv: sla cohorts: %w", err)
	}
	for rows2.Next() {
		var seg SLASegment
		if err := rows2.Scan(&seg.Source, &seg.ContentType, &seg.Cohort, &seg.N); err != nil {
			rows2.Close()
			return rep, err
		}
		rep.Segments = append(rep.Segments, seg)
	}
	rows2.Close()
	if err := rows2.Err(); err != nil {
		return rep, err
	}

	oq := legDurationsCTE + `
		SELECT count(*) FILTER (WHERE cohort='open'),
			(max(EXTRACT(EPOCH FROM (now() - observed_at))) FILTER (WHERE cohort='open'))::bigint
		FROM legdur WHERE anchor_at >= $1`
	if err := s.pool.QueryRow(ctx, oq, since).Scan(&rep.OpenCount, &rep.OldestOpenSeconds); err != nil {
		return rep, fmt.Errorf("tcv: sla open: %w", err)
	}

	iq := legDurationsCTE + ` SELECT COALESCE(bool_or(incomplete OR anomalous), false) FROM legdur WHERE anchor_at >= $1`
	if err := s.pool.QueryRow(ctx, iq, since).Scan(&rep.IncompleteWindow); err != nil {
		return rep, fmt.Errorf("tcv: sla incomplete: %w", err)
	}

	// Bottleneck: largest validated P95 among the component stages. e2e is the
	// whole-pipeline total and would dominate by construction, so it is excluded.
	bq := legDurationsCTE + `
		SELECT
			percentile_cont(0.95) WITHIN GROUP (ORDER BY CASE WHEN cohort='validated' AND NOT incomplete AND NOT anomalous THEN queue_sec END),
			percentile_cont(0.95) WITHIN GROUP (ORDER BY CASE WHEN cohort='validated' AND NOT incomplete AND NOT anomalous THEN gen_sec END),
			percentile_cont(0.95) WITHIN GROUP (ORDER BY CASE WHEN cohort='validated' AND NOT incomplete AND NOT anomalous THEN val_sec END)
		FROM legdur WHERE anchor_at >= $1`
	var pq, pg, pv *float64
	if err := s.pool.QueryRow(ctx, bq, since).Scan(&pq, &pg, &pv); err != nil {
		return rep, fmt.Errorf("tcv: sla bottleneck: %w", err)
	}
	rep.Bottleneck = largestStage(map[Stage]*float64{StageQueue: pq, StageGeneration: pg, StageValidation: pv})
	return rep, nil
}

func largestStage(p95 map[Stage]*float64) Stage {
	var best Stage
	var bestV float64
	for _, st := range []Stage{StageQueue, StageGeneration, StageValidation} {
		if v := p95[st]; v != nil && (best == "" || *v > bestV) {
			best, bestV = st, *v
		}
	}
	return best
}
