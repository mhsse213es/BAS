package evidence

import (
	"context"
	"strings"
	"testing"
	"time"
)

func strptr(s string) *string { return &s }

func TestRecordGenerationAttempt_NullableFieldsStayNull(t *testing.T) {
	s := NewStore(sharedDB.Pool)

	err := s.RecordGenerationAttempt(context.Background(), GenerationAttempt{
		CycleID: "cycle-1", Outcome: "skipped", ReasonCode: "unresolved_identity",
		GeneratorVersion: "4", StartedAt: time.Now(),
		// ThreatID, ContentID, ContentVersionID, Fingerprint, Detail: nil
	})
	if err != nil {
		t.Fatalf("RecordGenerationAttempt: %v", err)
	}

	got, err := s.ListGenerationAttempts(context.Background(), GenerationAttemptFilter{CycleID: "cycle-1"})
	if err != nil {
		t.Fatalf("ListGenerationAttempts: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(got))
	}
	if got[0].ThreatID != nil || got[0].ContentID != nil || got[0].ContentVersionID != nil || got[0].Fingerprint != nil {
		t.Fatalf("expected nullable fields to come back nil, got %+v", got[0])
	}
}

func TestRecordGenerationAttempt_DetailTruncatedNotRejected(t *testing.T) {
	s := NewStore(sharedDB.Pool)

	huge := strptr(strings.Repeat("x", 5000))
	err := s.RecordGenerationAttempt(context.Background(), GenerationAttempt{
		CycleID: "cycle-2", Outcome: "failed", ReasonCode: "registrar_error",
		GeneratorVersion: "4", StartedAt: time.Now(), Detail: huge,
	})
	if err != nil {
		t.Fatalf("RecordGenerationAttempt must not fail on an over-length detail: %v", err)
	}

	got, err := s.ListGenerationAttempts(context.Background(), GenerationAttemptFilter{CycleID: "cycle-2"})
	if err != nil {
		t.Fatalf("ListGenerationAttempts: %v", err)
	}
	if got[0].Detail == nil || len(*got[0].Detail) > maxDetailBytes {
		t.Fatalf("expected detail truncated to %d bytes, got length %v", maxDetailBytes, got[0].Detail)
	}
}

func TestRecordGenerationAttempt_RejectsInvalidOutcome(t *testing.T) {
	s := NewStore(sharedDB.Pool)

	err := s.RecordGenerationAttempt(context.Background(), GenerationAttempt{
		CycleID: "cycle-3", Outcome: "not-a-real-outcome", ReasonCode: "ok",
		GeneratorVersion: "4", StartedAt: time.Now(),
	})
	if err == nil {
		t.Fatal("expected an invalid outcome to be rejected by the DB CHECK constraint")
	}
}

func TestListGenerationAttempts_FiltersByThreatIDAndLimit(t *testing.T) {
	s := NewStore(sharedDB.Pool)
	ctx := context.Background()
	// "threat-a"/"threat-b" are unique to this test within the package --
	// content_generation_attempts is a brand-new table no other existing
	// test in this package touches, and this package's sharedDB.Pool has
	// no per-test truncation (see the package-convention note above).
	threatA := strptr("threat-a")
	for i := 0; i < 3; i++ {
		if err := s.RecordGenerationAttempt(ctx, GenerationAttempt{
			CycleID: "cycle-x", ThreatID: threatA, Outcome: "created", ReasonCode: "ok",
			GeneratorVersion: "4", StartedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed attempt %d: %v", i, err)
		}
	}
	if err := s.RecordGenerationAttempt(ctx, GenerationAttempt{
		CycleID: "cycle-x", ThreatID: strptr("threat-b"), Outcome: "created", ReasonCode: "ok",
		GeneratorVersion: "4", StartedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed threat-b attempt: %v", err)
	}

	got, err := s.ListGenerationAttempts(ctx, GenerationAttemptFilter{ThreatID: "threat-a", Limit: 2})
	if err != nil {
		t.Fatalf("ListGenerationAttempts: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected limit=2 to cap results at 2, got %d", len(got))
	}
	for _, a := range got {
		if a.ThreatID == nil || *a.ThreatID != "threat-a" {
			t.Fatalf("expected only threat-a rows, got %+v", a)
		}
	}
}
