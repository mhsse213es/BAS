package pipelinecheck

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestCleanupPreview_LabInstance runs the preview against a real Elasticsearch lab index. It is
// skipped unless AUDSPECT_ES_LAB_URL is set, and expects the scratch index lab-cleanup-probe to
// hold one tagged record for previewRunID, one tagged record for another run, and one record
// for this run without the tag.
func TestCleanupPreview_LabInstance(t *testing.T) {
	base := os.Getenv("AUDSPECT_ES_LAB_URL")
	if base == "" {
		t.Skip("AUDSPECT_ES_LAB_URL not set")
	}
	cfg := ElasticConfig{BaseURL: base, Username: os.Getenv("AUDSPECT_ES_LAB_USER"), Password: os.Getenv("AUDSPECT_ES_LAB_PASS")}
	const index = "lab-cleanup-probe"
	old := time.Now().UTC().Add(-RetentionWindow - 24*time.Hour).Format(time.RFC3339Nano)
	recent := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	seedLab(t, cfg, index, "tagged-this-run", `{"audspect":{"test_run":"`+previewRunID+`"},"@timestamp":"`+old+`","tags":["audspect-bas-test"]}`)
	seedLab(t, cfg, index, "tagged-recent", `{"audspect":{"test_run":"`+previewRunID+`"},"@timestamp":"`+recent+`","tags":["audspect-bas-test"]}`)
	p := PreviewElasticCleanup(context.Background(), http.DefaultClient, cfg, index, previewRunID)
	if p.Status != "previewed" {
		t.Fatalf("preview status = %s (%s)", p.Status, p.Reason)
	}
	if len(p.Candidates) != 1 || p.Candidates[0] != "tagged-this-run" {
		t.Fatalf("candidates = %v, want exactly [tagged-this-run]", p.Candidates)
	}
	if len(p.RetentionHeld) != 1 || p.RetentionHeld[0] != "tagged-recent" {
		t.Fatalf("retention held = %v, want the recent record held", p.RetentionHeld)
	}
	if len(p.Retained) != 0 {
		t.Fatalf("retained = %v, want none: the other-run and untagged records must not be returned at all", p.Retained)
	}
}
