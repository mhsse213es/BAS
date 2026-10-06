package verifysync

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/reporting"
)

// A transient content-lookup failure must NOT let the run be marked
// processed (auto_verified=true): processRun returns an error so Tick
// retries it next time instead of silently losing its automatic verdicts.
// The unreadable check runs before any DB access, so no pool is needed.
func TestProcessRun_TransientUnreadableContentRetries(t *testing.T) {
	job := NewJob(nil, nil, nil).WithRunContent(func(context.Context, string) reporting.RunContentInfo {
		return reporting.RunContentInfo{Status: "unreadable", Label: "Content version unreadable", Transient: true}
	})
	if err := job.processRun(context.Background(), "run-t", "sc", nil); err == nil {
		t.Fatal("transient unreadable content must return an error so the run is retried")
	}
}

// A permanently unreadable run is marked processed (nil error) so it can't
// starve the LIMIT-bounded batch forever.
func TestProcessRun_PermanentUnreadableContentIsSkipped(t *testing.T) {
	job := NewJob(nil, nil, nil).WithRunContent(func(context.Context, string) reporting.RunContentInfo {
		return reporting.RunContentInfo{Status: "unreadable", Label: "Content version unreadable"}
	})
	if err := job.processRun(context.Background(), "run-p", "sc", nil); err != nil {
		t.Fatalf("permanent unreadable content must be skipped, got %v", err)
	}
}
