package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/audspect/bas/internal/compliance"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// mustMapper loads the real embedded-FS compliance mapper or fails the test.
func mustMapper(t *testing.T) *compliance.Mapper {
	t.Helper()
	m, err := compliance.NewMapper()
	if err != nil {
		t.Fatalf("compliance.NewMapper: %v", err)
	}
	return m
}

// newReportingHandler builds a Handler wired with a real reporting engine and
// compliance mapper. CHROME_WS_URL is cleared so PDF rendering deterministically
// takes the built-in fpdf fallback rather than the Chromium sidecar.
func newReportingHandler(t *testing.T, pool *pgxpool.Pool, engine *scenario.Engine) *Handler {
	t.Helper()
	t.Setenv("CHROME_WS_URL", "")
	if engine == nil {
		engine = scenario.NewEngine(t.TempDir())
	}
	return New(pool, ws.NewHub(), engine, "").
		WithReporting(reporting.NewEngine(pool).WithScenarios(engine)).
		WithCompliance(mustMapper(t))
}

// canonicalResults is the realistic multi-verdict payload that drives almost
// every 3d.1 report test: all four verdicts, three ATT&CK techniques across two
// tactics, a severity spread, remediation text on the FAILs (drives
// recommendations), and evidence fields on at least one result. Timestamps are
// fixed (never time.Now()) so nothing here is non-deterministic.
//
// CleanupVerdict is populated on every result on purpose: the report template
// compares .cleanupVerdict as a string ({{if eq .cleanupVerdict "reverted"}},
// html.go:2589), and because the report renders via a json-tag map (garble
// reflection constraint) an omitempty-dropped empty verdict becomes a missing
// map key that the template then compares against a string and errors on. A
// real completed posture run reports a cleanup verdict per technique, so a
// non-empty value here is the realistic shape — see the phase note flagging the
// underlying template robustness gap in internal/reporting.
func canonicalResults() []models.SimulationResult {
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	return []models.SimulationResult{
		{
			ID:             "res-fail-crit",
			Technique:      models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"},
			Result:         models.ResultFail,
			Severity:       "Critical",
			ThreatImpact:   "Arbitrary code execution",
			Details:        "PowerShell downgrade attack succeeded",
			Remediation:    "Enable Constrained Language Mode and script-block logging",
			RawOutput:      "PS> IEX(...)",
			Command:        "powershell -enc ...",
			ExitCode:       0,
			DurationMs:     1200,
			CleanupVerdict: "reverted",
			ExecutedAt:     base,
			StartedAt:      base,
		},
		{
			ID:             "res-fail-high",
			Technique:      models.AttackTechnique{ID: "T1003.001", Name: "LSASS Memory", Tactic: "credential-access"},
			Result:         models.ResultFail,
			Severity:       "High",
			ThreatImpact:   "Credential theft",
			Details:        "LSASS dump not blocked",
			Remediation:    "Enable Credential Guard and LSA protection",
			CleanupVerdict: "reverted",
			ExecutedAt:     base.Add(1 * time.Minute),
			StartedAt:      base.Add(1 * time.Minute),
		},
		{
			ID:             "res-pass",
			Technique:      models.AttackTechnique{ID: "T1547.001", Name: "Registry Run Keys", Tactic: "persistence"},
			Result:         models.ResultPass,
			Severity:       "Medium",
			Details:        "Run-key write blocked by control",
			CleanupVerdict: "reverted",
			ExecutedAt:     base.Add(2 * time.Minute),
			StartedAt:      base.Add(2 * time.Minute),
		},
		{
			ID:             "res-error",
			Technique:      models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"},
			Result:         models.ResultError,
			Severity:       "Low",
			Details:        "Technique errored (missing prerequisite)",
			CleanupVerdict: "reverted",
			ExecutedAt:     base.Add(3 * time.Minute),
			StartedAt:      base.Add(3 * time.Minute),
		},
		{
			ID:             "res-skipped",
			Technique:      models.AttackTechnique{ID: "T1112", Name: "Modify Registry", Tactic: "defense-evasion"},
			Result:         models.ResultSkipped,
			Severity:       "Low",
			Details:        "Skipped — OS mismatch",
			CleanupVerdict: "reverted",
			ExecutedAt:     base.Add(4 * time.Minute),
			StartedAt:      base.Add(4 * time.Minute),
		},
	}
}

type reportRunOpts struct {
	Status            string
	StartedAt         time.Time
	CampaignID        string
	Name              string
	Results           []models.SimulationResult
	TechniqueOverride string
	Reverted          []string
}

// seedReportableRun inserts a rich agents row (all report-relevant columns
// populated so the report engine renders a hostname and security context) and a
// scenario_runs row carrying a realistic results payload plus non-zero
// alerts/perf columns (so GetRunReportData's column read is observable).
//
// started_at and campaign_id are passed as explicit positional params (typed
// NULL when unset) so the query text is fixed — no dynamic index building.
func seedReportableRun(t *testing.T, pool *pgxpool.Pool, runID, agentID string, opts reportRunOpts) {
	t.Helper()
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (agent_id, hostname, ip_address, os_version, username, status, env_label, state, security_products)
		 VALUES ($1,$2,'10.0.0.5','Windows 11','svc-bas','idle','Production','active','["Defender"]')
		 ON CONFLICT (agent_id) DO NOTHING`,
		agentID, "host-"+agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	results := opts.Results
	if results == nil {
		results = canonicalResults()
	}
	if opts.TechniqueOverride != "" {
		results = []models.SimulationResult{{
			ID:             "res-" + opts.TechniqueOverride,
			Technique:      models.AttackTechnique{ID: opts.TechniqueOverride, Name: "Override", Tactic: "execution"},
			Result:         models.ResultFail,
			Severity:       "High",
			CleanupVerdict: "reverted",
			ExecutedAt:     time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
			StartedAt:      time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		}}
	}
	resultsJSON, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	revertedJSON, err := json.Marshal(opts.Reverted)
	if err != nil {
		t.Fatalf("marshal reverted: %v", err)
	}

	status := opts.Status
	if status == "" {
		status = "completed"
	}
	name := opts.Name
	if name == "" {
		name = "Report Test Run"
	}

	var startedAt *time.Time
	if !opts.StartedAt.IsZero() {
		startedAt = &opts.StartedAt
	}
	var campaignID *string
	if opts.CampaignID != "" {
		campaignID = &opts.CampaignID
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO scenario_runs
		   (id, scenario_id, agent_id, name, status, results, started_at, campaign_id, reverted,
		    alerts_total, alerts_high_fidelity, noise_score,
		    perf_cpu_before, perf_cpu_after, perf_ram_before, perf_ram_after, perf_disk_before, perf_disk_after)
		 VALUES ($1,'sc-report',$2,$3,$4,$5, COALESCE($6::timestamptz, NOW()), $7, $8,
		    42, 7, 3.5, 10, 25, 30, 55, 1, 2)`,
		runID, agentID, name, status, resultsJSON, startedAt, campaignID, revertedJSON); err != nil {
		t.Fatalf("seed reportable run: %v", err)
	}
}

func seedCampaign(t *testing.T, pool *pgxpool.Pool, campaignID, scenarioName string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO campaigns (id, name, scenario_id, scenario_name, mode)
		 VALUES ($1,$2,'sc-report',$3,'posture')`,
		campaignID, "Campaign "+campaignID, scenarioName); err != nil {
		t.Fatalf("seed campaign: %v", err)
	}
}
