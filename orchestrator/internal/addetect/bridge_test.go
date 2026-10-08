package addetect

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/detectverify"
)

func TestVerifyRequestFor_NoTechniqueIDReturnsFalse(t *testing.T) {
	p := adprimitive.Primitive{ID: "acl-forcechangepassword-abuse"} // no TechniqueID
	_, ok := VerifyRequestFor(p, "run-1", "exp-1", "HOST01", "10.0.0.5", time.Time{}, time.Time{}, time.Time{})
	if ok {
		t.Fatal("expected ok=false for a primitive with no TechniqueID")
	}
}

func TestVerifyRequestFor_MapsEveryFieldUnchanged(t *testing.T) {
	p := adprimitive.Primitive{ID: "dcsync", TechniqueID: "T1003.006"}
	executedAt := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	windowStart := executedAt.Add(-5 * time.Minute)
	windowEnd := executedAt.Add(10 * time.Minute)

	got, ok := VerifyRequestFor(p, "run-1", "exp-42", "DC01", "10.0.0.10", executedAt, windowStart, windowEnd)
	if !ok {
		t.Fatal("expected ok=true for a primitive with a TechniqueID")
	}
	want := detectverify.VerifyRequest{
		RunID:          "run-1",
		ExpectationID:  "exp-42",
		TechniqueID:    "T1003.006",
		HostName:       "DC01",
		HostIP:         "10.0.0.10",
		StepExecutedAt: executedAt,
		WindowStart:    windowStart,
		WindowEnd:      windowEnd,
	}
	if got != want {
		t.Fatalf("expected %+v, got %+v", want, got)
	}
}
