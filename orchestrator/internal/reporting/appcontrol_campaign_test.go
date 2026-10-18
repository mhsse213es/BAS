package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A campaign report renders one section per child run, each labelled with its
// host, and never merges runs together.
func TestGenerateHTML_CampaignRendersOneSectionPerRun(t *testing.T) {
	secA := buildAppControlSection("camp-run-a", []models.SimulationResult{
		appCtlResult("Application control indirect execution via cmd.exe parent (T1202)", "T1202", appCtlIndirectOut),
	})
	secA.Hostname = "host-alpha"
	secB := buildAppControlSection("camp-run-b", []models.SimulationResult{
		appCtlResult("Application control alternate binary: renamed powershell.exe copy (T1036)", "T1036",
			"APPCTL_FAMILY: alternate_binary\nAPPCTL_DETECTION: source=sysmon_process_create result=not_visible\nAPPCTL_OUTCOME: allowed_unexpectedly\n"),
	})
	secB.Hostname = "host-beta"
	rep := &FullReport{GeneratedAt: time.Now().UTC(), AppControlRuns: []AppControlSection{secA, secB}}

	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	html := buf.String()
	if n := strings.Count(html, "Application Control Efficacy"); n < 2 {
		t.Fatalf("want one section per run (>=2 headings), got %d", n)
	}
	for _, want := range []string{"host-alpha", "host-beta", "blocked_as_expected", "allowed_unexpectedly"} {
		if !strings.Contains(html, want) {
			t.Errorf("campaign report missing %q", want)
		}
	}
}

// BuildFromCampaign keeps each child run's evidence attached to that run and
// labels it with the run's host.
func TestBuildFromCampaign_AppControlPerRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		e := NewEngine(pool)
		const campaign = "camp-appctl"
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname) VALUES ('ag-alpha','host-alpha'),('ag-beta','host-beta')`); err != nil {
			t.Fatalf("seed agents: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO campaigns (id, name, scenario_id, scenario_name) VALUES ($1,'AppCtl campaign','scen-appctl','Application Control Efficacy')`, campaign); err != nil {
			t.Fatalf("seed campaign: %v", err)
		}
		seedCampaignChild(t, pool, "camp-run-a", "ag-alpha", campaign, []models.SimulationResult{
			appCtlResult("Application control indirect execution via cmd.exe parent (T1202)", "T1202", appCtlIndirectOut),
		})
		seedCampaignChild(t, pool, "camp-run-b", "ag-beta", campaign, []models.SimulationResult{
			appCtlResult("Application control alternate binary: renamed powershell.exe copy (T1036)", "T1036",
				"APPCTL_FAMILY: alternate_binary\nAPPCTL_DETECTION: source=sysmon_process_create result=not_visible\nAPPCTL_OUTCOME: allowed_unexpectedly\n"),
		})

		rep, err := e.BuildFromCampaign(ctx, campaign, "all")
		if err != nil {
			t.Fatalf("BuildFromCampaign: %v", err)
		}
		if len(rep.AppControlRuns) != 2 {
			t.Fatalf("want one section per child run, got %d", len(rep.AppControlRuns))
		}
		byRun := map[string]AppControlSection{}
		for _, s := range rep.AppControlRuns {
			byRun[s.RunID] = s
		}
		a, b := byRun["camp-run-a"], byRun["camp-run-b"]
		if a.Hostname != "host-alpha" || len(a.Rows) != 1 || a.Rows[0].Family != "indirect_execution" {
			t.Errorf("run A section = %+v, want host-alpha with its own indirect row only", a)
		}
		if b.Hostname != "host-beta" || len(b.Rows) != 1 || b.Rows[0].Family != "alternate_binary" {
			t.Errorf("run B section = %+v, want host-beta with its own alternate row only", b)
		}
		if rep.AppControl.HasData {
			t.Error("campaign report must not use the single-run section; runs are not merged")
		}
	})
}

func seedCampaignChild(t *testing.T, pool *pgxpool.Pool, id, agent, campaign string, results []models.SimulationResult) {
	t.Helper()
	rj, _ := json.Marshal(results)
	sj, _ := json.Marshal(models.Score{PreventionScore: 50, RiskScore: 50})
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, score, started_at, campaign_id)
		 VALUES ($1,'scen-appctl',$2,'Application Control Efficacy','completed',$3,$4, NOW(), $5)`,
		id, agent, rj, sj, campaign); err != nil {
		t.Fatalf("seed child run %s: %v", id, err)
	}
}
