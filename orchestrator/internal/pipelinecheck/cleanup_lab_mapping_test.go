package pipelinecheck

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func labCfg(t *testing.T) ElasticConfig {
	t.Helper()
	base := os.Getenv("AUDSPECT_ES_LAB_URL")
	if base == "" {
		t.Skip("AUDSPECT_ES_LAB_URL not set")
	}
	return ElasticConfig{BaseURL: base, Username: os.Getenv("AUDSPECT_ES_LAB_USER"), Password: os.Getenv("AUDSPECT_ES_LAB_PASS")}
}

// With explicit keyword fields the exact match and the phrase match both find the record, and the
// exact check confirms it.
func TestCleanupPreview_LabKeywordMapping(t *testing.T) {
	cfg := labCfg(t)
	old := time.Now().UTC().Add(-RetentionWindow - 24*time.Hour).Format(time.RFC3339Nano)
	seedLab(t, cfg, "lab-keyword-probe", "keyword-run", `{"audspect":{"test_run":"`+previewRunID+`"},"@timestamp":"`+old+`","tags":["audspect-bas-test"]}`)
	p := PreviewElasticCleanup(context.Background(), http.DefaultClient, cfg, "lab-keyword-probe", previewRunID)
	if p.Status != "previewed" || len(p.Candidates) != 1 || p.Candidates[0] != "keyword-run" {
		t.Fatalf("keyword mapping: preview = %+v, want exactly [keyword-run]", p)
	}
}

// An index where the marker fields were never indexed must not present zero matches as an
// empty result. It must be an error.
func TestCleanupPreview_LabUnmappedIndexIsErrorNotEmpty(t *testing.T) {
	cfg := labCfg(t)
	p := PreviewElasticCleanup(context.Background(), http.DefaultClient, cfg, "lab-unmapped-probe", previewRunID)
	if p.Status != "error" || !strings.Contains(p.Reason, "not mapped") {
		t.Fatalf("unmapped lab index: preview = %+v, want an error, not a previewed empty list", p)
	}
}
