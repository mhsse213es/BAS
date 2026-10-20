package pipelinecheck

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// seedLab writes one document into the lab index, replacing any existing copy, so the test does not
// depend on what an earlier run left behind.
func seedLab(t *testing.T, cfg ElasticConfig, index, id, body string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, strings.TrimRight(cfg.BaseURL, "/")+"/"+index+"/_doc/"+id+"?refresh=true",
		strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(cfg.Username, cfg.Password)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Fatalf("seed %s: HTTP %d", id, resp.StatusCode)
	}
}

// Against the lab: only records with this run identifier AND the tag are deleted. A record with a
// different run identifier, or with the run identifier but no tag, survives. The test seeds its own
// records each run, so it is repeatable.
func TestDeleteCandidates_LabDeletesOnlyExactMatches(t *testing.T) {
	cfg := labCfg(t)
	const index = "lab-delete-probe"
	seedLab(t, cfg, index, "mine-1", `{"audspect":{"test_run":"`+previewRunID+`"},"@timestamp":"`+oldEvent()+`","tags":["audspect-bas-test"]}`)
	seedLab(t, cfg, index, "mine-2", `{"audspect":{"test_run":"`+previewRunID+`"},"@timestamp":"`+oldEvent()+`","tags":["audspect-bas-test"]}`)
	seedLab(t, cfg, index, "other-run", `{"audspect":{"test_run":"bas-ffffffffffffffffffffffffffffffff"},"@timestamp":"`+oldEvent()+`","tags":["audspect-bas-test"]}`)
	seedLab(t, cfg, index, "untagged", `{"audspect":{"test_run":"`+previewRunID+`"},"@timestamp":"`+oldEvent()+`","tags":["team-a"]}`)

	ids := []string{"mine-1", "mine-2", "other-run", "untagged"}
	res, err := DeleteElasticCandidates(context.Background(), http.DefaultClient, cfg, index, previewRunID, ids, testCutoff)
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted != 2 {
		t.Fatalf("deleted %d records, want exactly the two tagged records of this run: %+v", res.Deleted, res)
	}
	p := PreviewElasticCleanup(context.Background(), http.DefaultClient, cfg, index, previewRunID)
	if p.Status != "previewed" || len(p.Candidates) != 0 {
		t.Fatalf("after delete, preview = %+v, want no candidates left", p)
	}
}

// oldEvent is an event time well outside the retention window, so the seeded records are eligible.
func oldEvent() string {
	return time.Now().UTC().Add(-RetentionWindow - 24*time.Hour).Format(time.RFC3339Nano)
}
