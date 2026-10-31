package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/tcv"
	"github.com/audspect/bas/internal/ws"
)

// seedValidatedLeg builds one fully-validated (threat, emulates) leg: the
// scenario/content_version/threat rows the leg references plus the four
// pipeline events that span observed→validated.
func seedValidatedLeg(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	mustExec := func(q string, args ...any) {
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	mustExec(`INSERT INTO scenarios (scenario_id, name, category, origin) VALUES ('sla-cv','sla-cv','','LOCAL') ON CONFLICT (scenario_id) DO NOTHING`)
	var vid string
	if err := pool.QueryRow(ctx, `INSERT INTO content_versions
		(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes, trust_level, lifecycle,
		 intake_source, schema_version, technique_ids, supported_os, generation, created_by)
		VALUES ('sla-cv','LOCAL',1,'deadbeef',0,'\x','LOCAL_TRUSTED','PUBLISHED_LOCAL','custom',1,'{}','{}','{}'::jsonb,'test')
		RETURNING id`).Scan(&vid); err != nil {
		t.Fatal(err)
	}
	var threatID string
	if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ('APT-sla-handler','{}') RETURNING id`).Scan(&threatID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
		VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, 'APT-sla-handler') RETURNING id`, threatID).Scan(&threatID); err != nil {
		t.Fatal(err)
	}
	mustExec(`INSERT INTO content_version_threats (content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
		VALUES ($1,$2,'emulates','admin','r')`, vid, threatID)

	t0 := time.Now().Add(-2 * time.Hour)
	rec := func(e tcv.Event) {
		if err := tcv.RecordPipelineEvent(ctx, pool, e); err != nil {
			t.Fatalf("seed event %s: %v", e.Type, err)
		}
	}
	rec(tcv.Event{Type: tcv.EventThreatObserved, ThreatID: threatID, EventTime: t0,
		SourceTable: "source_observations", SourcePK: threatID, Payload: map[string]any{"source": "misp"}})
	rec(tcv.Event{Type: tcv.EventThreatEligible, ThreatID: threatID, EventTime: t0.Add(time.Minute),
		SourceTable: "content_generation_cycle", SourcePK: threatID})
	rec(tcv.Event{Type: tcv.EventContentCreated, ThreatID: threatID, ContentVersionID: vid,
		GenerationAttemptID: "cga-" + vid, EventTime: t0.Add(2 * time.Minute),
		SourceTable: "content_generation_attempts", SourcePK: "cga-" + vid, Payload: map[string]any{"outcome": "created"}})
	rec(tcv.Event{Type: tcv.EventValidatedCoverage, ContentVersionID: vid, EventTime: t0.Add(5 * time.Minute),
		SourceTable: "content_version_events", SourcePK: "cve-" + vid, Payload: map[string]any{"to_lifecycle": "VALIDATED"}})
}

func TestFactorySLAHandler_ReturnsReport(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedValidatedLeg(t, pool)

		h := New(pool, ws.NewHub(), nil, "")
		req := httptest.NewRequest(http.MethodGet, "/x?stage=end_to_end", nil)
		rec := httptest.NewRecorder()
		h.GetFactorySLA(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}
		var report tcv.SLAReport
		if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
			t.Fatalf("decode: %v body=%s", err, rec.Body.String())
		}
		if report.Stage != tcv.StageEndToEnd {
			t.Fatalf("stage=%q, want end_to_end", report.Stage)
		}
		var validated *tcv.SLASegment
		for i := range report.Segments {
			if report.Segments[i].Cohort == "validated" && report.Segments[i].ContentType == "emulates" {
				validated = &report.Segments[i]
			}
		}
		if validated == nil || validated.N != 1 || validated.P50Seconds == nil {
			t.Fatalf("expected one validated emulates segment with P50, got %+v", report.Segments)
		}
	})
}
