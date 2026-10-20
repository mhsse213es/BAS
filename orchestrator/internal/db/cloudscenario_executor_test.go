package db_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/cloudrun"
	"github.com/audspect/bas/internal/db"
)

const (
	scnDBPrincipal = "arn:aws:iam::111:user/ops"
	scnDBVault     = "arn:aws:backup:us-east-1:111:backup-vault:prod"
)

// scenarioGraph returns a graph with the principal and vault present and one
// identity-policy edge per allowed action.
func scenarioGraph(actions ...string) *cloudgraph.DiscoveredGraph {
	id := &cloudgraph.CloudIdentity{CanonicalID: scnDBPrincipal, Kind: "iam-user"}
	res := &cloudgraph.CloudResource{CanonicalID: scnDBVault, Kind: "backup-vault"}
	g := &cloudgraph.DiscoveredGraph{
		Identities:  []*cloudgraph.CloudIdentity{id},
		Resources:   []*cloudgraph.CloudResource{res},
		Evaluations: map[string]cloudgraph.PathState{},
	}
	for _, a := range actions {
		g.Permissions = append(g.Permissions, &cloudgraph.CloudPermission{
			Source: id, Target: res, Action: a, SourceType: "identity-policy",
			Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"` + a + `"}]}`},
		})
	}
	return g
}

// scenarioEvents is a fixed live log source for observation tests.
type scenarioEvents struct{ events []*cloudgraph.CloudEvent }

func (s scenarioEvents) Name() string { return "cloudtrail" }
func (s scenarioEvents) Fetch(context.Context, cloudgraph.EventQuery) ([]*cloudgraph.CloudEvent, bool, error) {
	return s.events, false, nil
}

func scenarioRunReq(d cloudgraph.Discoverer) db.CloudScenarioRunRequest {
	return db.CloudScenarioRunRequest{
		ScenarioID: "backup-assurance-aws",
		Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
		Principal:  scnDBPrincipal,
		Resource:   scnDBVault,
		Discoverer: d,
	}
}

func TestExecuteCloudScenarioRun_LiveDiscoveryGivesPartialVerdict(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		disc := &fakeDiscoverer{graph: scenarioGraph("backup:ListRecoveryPointsByBackupVault")}
		run, err := db.ExecuteCloudScenarioRun(context.Background(), pool, scenarioRunReq(disc))
		if err != nil {
			t.Fatalf("ExecuteCloudScenarioRun: %v", err)
		}
		if run.Status != cloudrun.StatusCompleted {
			t.Fatalf("status = %s, want completed", run.Status)
		}
		var res struct {
			Verdict string `json:"verdict"`
			Steps   []struct {
				ExecutionOutcome string `json:"ExecutionOutcome"`
			} `json:"steps"`
		}
		if err := json.Unmarshal(run.Result, &res); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if res.Verdict != "partially-blocked" || len(res.Steps) != 2 {
			t.Errorf("verdict = %s, steps = %d; want partially-blocked over 2 steps", res.Verdict, len(res.Steps))
		}
	})
}

func TestExecuteCloudScenarioRun_ObservedMissingEvidenceIsUnknown(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		disc := &fakeDiscoverer{graph: scenarioGraph("backup:ListRecoveryPointsByBackupVault")}
		req := scenarioRunReq(disc)
		req.Observe = &db.ObserveSpec{
			ActionTime: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC),
			Window:     time.Minute,
			Events:     scenarioEvents{},
		}
		run, err := db.ExecuteCloudScenarioRun(context.Background(), pool, req)
		if err != nil {
			t.Fatalf("ExecuteCloudScenarioRun: %v", err)
		}
		var res struct {
			Observed bool   `json:"observed"`
			Verdict  string `json:"verdict"`
		}
		if err := json.Unmarshal(run.Result, &res); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !res.Observed || res.Verdict != "inconclusive" {
			t.Errorf("observed=%v verdict=%s; no audit evidence must make the verdict inconclusive", res.Observed, res.Verdict)
		}
		if run.Status != cloudrun.StatusPartial {
			t.Errorf("inconclusive run status = %s, want partial", run.Status)
		}
	})
}

func TestExecuteCloudScenarioRun_ProviderMismatchFailsRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		req := scenarioRunReq(&fakeDiscoverer{graph: scenarioGraph()})
		req.Account.Provider = "gcp"
		run, err := db.ExecuteCloudScenarioRun(context.Background(), pool, req)
		if err == nil || run == nil || run.Status != cloudrun.StatusFailed {
			t.Fatalf("provider mismatch must fail the row: run=%+v err=%v", run, err)
		}
	})
}

func TestExecuteCloudScenarioRun_DiscoveryErrorFailsRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		disc := &fakeDiscoverer{err: errors.New("AccessDenied listing backup vaults")}
		run, err := db.ExecuteCloudScenarioRun(context.Background(), pool, scenarioRunReq(disc))
		if err == nil || run.Status != cloudrun.StatusFailed {
			t.Fatalf("discovery failure must fail the row: %+v %v", run, err)
		}
	})
}
