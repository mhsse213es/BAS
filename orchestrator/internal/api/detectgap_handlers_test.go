package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/rulelib"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
	"github.com/audspect/bas/internal/ws"
)

type gapRow struct {
	TechniqueID      string `json:"techniqueId"`
	Status           string `json:"status"`
	Reason           string `json:"reason"`
	RuleAvailability string `json:"ruleAvailability"`
	Effectiveness    string `json:"effectiveness"`
	RuleCount        int    `json:"ruleCount"`
	Rules            []struct {
		ID       string `json:"id"`
		SigmaID  string `json:"sigmaId"`
		Source   struct{ Commit, License string }
		Backends []struct {
			Backend, Mapping, ExportURL string
		} `json:"backends"`
	} `json:"rules"`
}

type gapResp struct {
	RunID   string         `json:"runId"`
	Summary map[string]int `json:"summary"`
	Library struct {
		SigmaCommit string `json:"sigmaCommit"`
		License     string `json:"license"`
	} `json:"library"`
	Techniques []gapRow `json:"techniques"`
}

func seedGapRun(t *testing.T, pool *pgxpool.Pool, results []models.SimulationResult) string {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('a1', 'gap-host', 'active') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(results)
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO scenario_runs (scenario_id, agent_id, status, execution_kind, results) VALUES ('scn-gap', 'a1', 'completed', 'legacy', $1) RETURNING id`, raw).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func gapHandler(pool *pgxpool.Pool, t *testing.T) *Handler {
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
		WithVerificationStore(verification.NewStore(pool)).WithRuleLibrary(rulelib.NewEngine())
}

func getGaps(t *testing.T, h *Handler, runID, query string) (gapResp, int) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.GetRunDetectionGaps(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x"+query, nil), "runId", runID))
	var out gapResp
	json.Unmarshal(rec.Body.Bytes(), &out)
	return out, rec.Code
}

func attest(t *testing.T, pool *pgxpool.Pool, runID, tech, result, state string) {
	t.Helper()
	if _, err := verification.NewStore(pool).Attest(context.Background(), verification.AttestInput{
		RunID: runID, ExpectationID: "exp-" + tech + "-" + result, TechniqueID: tech, Result: result,
		WorkflowState: state, Source: verification.SourceManual, VerifiedBy: "analyst",
	}); err != nil {
		t.Fatal(err)
	}
}

func res(tech string, r models.CheckResult) models.SimulationResult {
	return models.SimulationResult{ID: tech + string(r), Technique: models.AttackTechnique{ID: tech, Name: tech}, Result: r}
}

func TestRunDetectionGaps_ClassifiesFromEvidenceAndAttachesTheRulesThatCouldCloseAGap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := gapHandler(pool, t)
		runID := seedGapRun(t, pool, []models.SimulationResult{
			res("T1059.001", models.ResultFail), // ran, reviewed miss -> gap
			res("T1003.001", models.ResultFail), // ran, reviewed detection
			res("T1547.001", models.ResultFail), // ran, never verified -> unknown
			res("T1047", models.ResultError),    // engine error
			res("T1070.001", models.ResultSkipped),
		})
		attest(t, pool, runID, "T1059.001", verification.ResultNotDetected, verification.StateApproved)
		attest(t, pool, runID, "T1003.001", verification.ResultDetected, verification.StateApproved)

		out, code := getGaps(t, h, runID, "")
		if code != http.StatusOK {
			t.Fatalf("status = %d", code)
		}
		want := map[string]string{"T1059.001": "Detection gap", "T1003.001": "Detected", "T1547.001": "Unknown",
			"T1047": "Execution error", "T1070.001": "Skipped"}
		got := map[string]gapRow{}
		for _, r := range out.Techniques {
			got[r.TechniqueID] = r
		}
		for tech, status := range want {
			if got[tech].Status != status || got[tech].Reason == "" {
				t.Errorf("%s: status %q (reason %q), want %q", tech, got[tech].Status, got[tech].Reason, status)
			}
		}
		if out.Summary["Detection gap"] != 1 || out.Summary["Detected"] != 1 || out.Summary["Unknown"] != 1 {
			t.Errorf("summary = %v", out.Summary)
		}
		if len(out.Library.SigmaCommit) != 40 || out.Library.License != "DRL-1.1" {
			t.Errorf("library provenance = %+v", out.Library)
		}

		gap := got["T1059.001"]
		if gap.RuleAvailability != "Rule available" || gap.Effectiveness != "Not validated" || gap.RuleCount == 0 || len(gap.Rules) == 0 {
			t.Fatalf("a gap must carry the rules that could close it, labelled as unvalidated: %+v", gap)
		}
		r0 := gap.Rules[0]
		if r0.SigmaID == "" || r0.Source.Commit != out.Library.SigmaCommit || len(r0.Backends) == 0 || r0.Backends[0].ExportURL == "" {
			t.Errorf("rule lacks upstream id, provenance or export links: %+v", r0)
		}
		// Only gaps carry rules by default; everything else stays light.
		if len(got["T1003.001"].Rules) != 0 || len(got["T1547.001"].Rules) != 0 {
			t.Error("non-gap techniques carried rules without asking")
		}
	})
}

func TestRunDetectionGaps_AMissStillAwaitingReviewIsNotAGapAndNoRuleIsSaidHonestly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := gapHandler(pool, t)
		runID := seedGapRun(t, pool, []models.SimulationResult{res("T1059.001", models.ResultFail), res("T9999", models.ResultFail)})
		attest(t, pool, runID, "T1059.001", verification.ResultNotDetected, verification.StatePending)
		attest(t, pool, runID, "T9999", verification.ResultNotDetected, verification.StateApproved)

		out, _ := getGaps(t, h, runID, "")
		byT := map[string]gapRow{}
		for _, r := range out.Techniques {
			byT[r.TechniqueID] = r
		}
		if byT["T1059.001"].Status != "Unknown" {
			t.Errorf("a pending miss became %q, want Unknown", byT["T1059.001"].Status)
		}
		if g := byT["T9999"]; g.Status != "Detection gap" || g.RuleAvailability != "No rule available" || len(g.Rules) != 0 {
			t.Errorf("a gap with no rule must say so and invent nothing: %+v", g)
		}
	})
}

func TestRunDetectionGaps_BackendFilterAndUnknownRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := gapHandler(pool, t)
		runID := seedGapRun(t, pool, []models.SimulationResult{res("T1059.001", models.ResultFail)})
		attest(t, pool, runID, "T1059.001", verification.ResultNotDetected, verification.StateApproved)
		out, _ := getGaps(t, h, runID, "?backend=splunk")
		for _, r := range out.Techniques[0].Rules {
			if len(r.Backends) != 1 || r.Backends[0].Backend != "splunk" {
				t.Fatalf("backend filter ignored: %+v", r.Backends)
			}
		}
		if _, code := getGaps(t, h, "00000000-0000-0000-0000-000000000000", ""); code != http.StatusNotFound {
			t.Errorf("unknown run = %d, want 404", code)
		}
	})
}

func getGapExport(t *testing.T, h *Handler, runID, query string) (*zip.Reader, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ExportRunDetectionGaps(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x"+query, nil), "runId", runID))
	if rec.Code != http.StatusOK {
		return nil, rec
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("export is not a zip: %v", err)
	}
	return zr, rec
}

func zipFiles(t *testing.T, zr *zip.Reader) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = string(b)
	}
	return out
}

func TestRunDetectionGapExport_BundlesRulesAndQueriesWithProvenanceAndNothingInvented(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := gapHandler(pool, t)
		runID := seedGapRun(t, pool, []models.SimulationResult{
			res("T1059.001", models.ResultFail), res("T9999", models.ResultFail), res("T1003.001", models.ResultFail),
		})
		attest(t, pool, runID, "T1059.001", verification.ResultNotDetected, verification.StateApproved)
		attest(t, pool, runID, "T9999", verification.ResultNotDetected, verification.StateApproved)
		attest(t, pool, runID, "T1003.001", verification.ResultDetected, verification.StateApproved)

		zr, rec := getGapExport(t, h, runID, "?backend=splunk")
		if zr == nil {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
			t.Errorf("Content-Type = %q", ct)
		}
		files := zipFiles(t, zr)

		notice := files["NOTICE.txt"]
		if !strings.Contains(notice, "Detection Rule License") || !strings.Contains(notice, "SigmaHQ") || !strings.Contains(notice, "0e3b749e0d85cd943706ed610a1447f0d54e8388") {
			t.Errorf("NOTICE lacks attribution, licence or commit:\n%s", notice)
		}
		var manifest struct {
			RunID         string `json:"runId"`
			Effectiveness string `json:"effectiveness"`
			Techniques    []struct {
				TechniqueID      string `json:"techniqueId"`
				RuleAvailability string `json:"ruleAvailability"`
				Rules            []struct {
					ID, SigmaID string
					Source      struct{ Commit, License string }
					Files       []string `json:"files"`
				} `json:"rules"`
			} `json:"techniques"`
		}
		if err := json.Unmarshal([]byte(files["manifest.json"]), &manifest); err != nil {
			t.Fatalf("manifest.json: %v", err)
		}
		if manifest.RunID != runID || manifest.Effectiveness != "Not validated" {
			t.Errorf("manifest header = %+v", manifest)
		}
		if len(manifest.Techniques) != 2 {
			t.Fatalf("manifest lists %d techniques, want only the 2 gaps (not the detected one)", len(manifest.Techniques))
		}
		for _, tq := range manifest.Techniques {
			if tq.TechniqueID == "T9999" && (tq.RuleAvailability != "No rule available" || len(tq.Rules) != 0) {
				t.Errorf("a gap with no rule must say so: %+v", tq)
			}
			for _, r := range tq.Rules {
				if r.Source.License != "DRL-1.1" || len(r.Files) < 2 {
					t.Fatalf("rule %s lacks licence or files: %+v", r.ID, r)
				}
				for _, f := range r.Files {
					if _, ok := files[f]; !ok {
						t.Errorf("manifest points at %q which is not in the bundle", f)
					}
				}
			}
		}
		var sawSigma, sawSPL bool
		for name, body := range files {
			if strings.HasSuffix(name, ".sigma.yml") && strings.Contains(body, "detection:") {
				sawSigma = true
			}
			if strings.HasPrefix(name, "queries/splunk/") && strings.HasSuffix(name, ".spl") && body != "" {
				sawSPL = true
			}
			if strings.HasPrefix(name, "queries/") && !strings.HasPrefix(name, "queries/splunk/") {
				t.Errorf("backend filter ignored: %s", name)
			}
			if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
				t.Errorf("unsafe path in bundle: %q", name)
			}
		}
		if !sawSigma || !sawSPL {
			t.Errorf("bundle lacks the original Sigma rule (%v) or a Splunk query (%v)", sawSigma, sawSPL)
		}
	})
}

// QRadar bundles use the .aql extension, and the manifest lists those files.
func TestRunDetectionGapExport_QRadarQueriesAreAQLFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := gapHandler(pool, t)
		runID := seedGapRun(t, pool, []models.SimulationResult{res("T1059.001", models.ResultFail)})
		attest(t, pool, runID, "T1059.001", verification.ResultNotDetected, verification.StateApproved)
		zr, rec := getGapExport(t, h, runID, "?backend=qradar")
		if zr == nil {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		saw := false
		for name, body := range zipFiles(t, zr) {
			if strings.HasPrefix(name, "queries/qradar/") {
				saw = true
				if !strings.HasSuffix(name, ".aql") || !strings.Contains(body, "events") {
					t.Errorf("bad QRadar file %s: %.80s", name, body)
				}
			}
		}
		if !saw {
			t.Error("no QRadar query in the bundle")
		}
	})
}

func TestRunDetectionGapExport_UnknownRunAndNothingToExport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := gapHandler(pool, t)
		if _, rec := getGapExport(t, h, "00000000-0000-0000-0000-000000000000", ""); rec.Code != http.StatusNotFound {
			t.Errorf("unknown run = %d, want 404", rec.Code)
		}
		runID := seedGapRun(t, pool, []models.SimulationResult{res("T1059.001", models.ResultFail)})
		if _, rec := getGapExport(t, h, runID, ""); rec.Code != http.StatusNotFound {
			t.Errorf("a run with no detection gap = %d, want 404 (nothing to export)", rec.Code)
		}
	})
}

// An Elastic export carries the Lucene query for every rule and, where one exists, the case-insensitive Elasticsearch
// DSL beside it: never instead of it.
func TestRunDetectionGapExport_ElasticHasLuceneAndCaseInsensitiveDSLFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := gapHandler(pool, t)
		runID := seedGapRun(t, pool, []models.SimulationResult{res("T1059.001", models.ResultFail)})
		attest(t, pool, runID, "T1059.001", verification.ResultNotDetected, verification.StateApproved)
		zr, rec := getGapExport(t, h, runID, "?backend=elastic")
		if zr == nil {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		files := zipFiles(t, zr)
		lucene, dsl := 0, 0
		for name, body := range files {
			switch {
			case strings.HasPrefix(name, "queries/elastic/") && strings.HasSuffix(name, ".lucene"):
				lucene++
			case strings.HasPrefix(name, "queries/elastic/") && strings.HasSuffix(name, ".dsl.json"):
				dsl++
				var doc map[string]any
				if err := json.Unmarshal([]byte(body), &doc); err != nil || doc["query"] == nil {
					t.Errorf("%s is not a DSL query: %v", name, err)
				}
				sibling := strings.TrimSuffix(name, ".dsl.json") + ".lucene"
				if _, ok := files[sibling]; !ok {
					t.Errorf("%s has no Lucene query beside it", name)
				}
			}
		}
		if lucene == 0 {
			t.Fatal("no Lucene query in the Elastic export")
		}
		if dsl == 0 {
			t.Error("no Elasticsearch DSL in the Elastic export")
		}
	})
}
