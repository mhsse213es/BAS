package pipelinecheck

import (
	"context"
	"net/http"
	"os"
	"testing"
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
	p := PreviewElasticCleanup(context.Background(), http.DefaultClient, cfg, "lab-cleanup-probe", previewRunID)
	if p.Status != "previewed" {
		t.Fatalf("preview status = %s (%s)", p.Status, p.Reason)
	}
	if len(p.Candidates) != 1 || p.Candidates[0] != "tagged-this-run" {
		t.Fatalf("candidates = %v, want exactly [tagged-this-run]", p.Candidates)
	}
	if len(p.Retained) != 0 {
		t.Fatalf("retained = %v, want none: the other-run and untagged records must not be returned at all", p.Retained)
	}
}
