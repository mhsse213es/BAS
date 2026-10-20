package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// fakeElastic answers every search with one canned status and body.
func fakeElastic(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func insertElasticConnector(t *testing.T, pool *pgxpool.Pool, id, baseURL string) {
	t.Helper()
	mustExecAPI(t, pool, `INSERT INTO detection_connectors (id, name, provider, enabled, auto_verify,
		azure_tenant_id, client_id, client_secret, workspace_id, base_url, api_token, insecure_tls, verify_delay_seconds)
		VALUES ($1, 'lab elastic', 'elastic', true, false, '', '', '', '', $2, 'lab-api-key', false, 0)
		ON CONFLICT (id) DO UPDATE SET base_url = EXCLUDED.base_url`, id, baseURL)
}

func pipelineCampaignDef(id, connectorID string, downstream bool) killchain.CampaignDef {
	stages := []killchain.StageDef{{Key: "ingest", Pipeline: &killchain.PipelineSpec{
		ConnectorID: connectorID, Index: "logs-*", Field: "event.id", Identifier: "bas-probe-1", LookbackMinutes: 15,
	}}}
	if downstream {
		stages = append(stages, killchain.StageDef{Key: "attack", ScenarioID: "credential-access", Requires: []string{"ingest"}})
	}
	return killchain.CampaignDef{ID: id, Name: id, Version: 1, Stages: stages}
}

// A reachable, authenticated connector with the probe event present: the ingestion stage
// is INCONCLUSIVE, the per-stage results are persisted, and no other stage is claimed.
func TestPipelineStage_VerifiedIngestionPersistsPerStageEvidence(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		es := fakeElastic(t, 200, `{"hits":{"total":{"value":1,"relation":"eq"},"hits":[
		  {"_id":"doc-1","_source":{"@timestamp":"2026-10-20T09:02:03Z"}}]}}`)
		defer es.Close()
		insertElasticConnector(t, pool, "dc-pipe-ok", es.URL)
		def := pipelineCampaignDef("pipe-ok-1", "dc-pipe-ok", false)
		if err := (db.KillChainStore{Pool: pool}).CreateCampaign(context.Background(), def, "owner-1", ""); err != nil {
			t.Fatal(err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		if rec := advance(h, def.ID, ""); rec.Code != http.StatusOK {
			t.Fatalf("advance: status=%d body=%s", rec.Code, rec.Body.String())
		}

		rec, err := (db.KillChainStore{Pool: pool}).Campaign(context.Background(), def.ID)
		if err != nil {
			t.Fatal(err)
		}
		st := rec.Stages["ingest"]
		if st.Verdict != killchain.VerdictInconclusive {
			t.Fatalf("verdict=%s reasons=%v, want INCONCLUSIVE", st.Verdict, st.Reasons)
		}
		if st.Evidence == nil || len(st.Evidence.Pipeline) != len(pipelinePersistStages()) {
			t.Fatalf("per-stage evidence not persisted: %+v", st.Evidence)
		}
		byStage := map[string]killchain.PipelineStageResult{}
		for _, r := range st.Evidence.Pipeline {
			byStage[r.Stage] = r
		}
		if byStage["ingestion"].Status != "VERIFIED" || byStage["ingestion"].MatchCount != 1 || len(byStage["ingestion"].EventIDs) != 1 {
			t.Fatalf("ingestion evidence: %+v", byStage["ingestion"])
		}
		if byStage["connectivity"].Status != "VERIFIED" {
			t.Fatalf("connectivity: %+v", byStage["connectivity"])
		}
		for _, s := range []string{"normalization", "correlation", "alert", "case", "routing", "acknowledgement", "escalation"} {
			if byStage[s].Status != "NOT_TESTED" {
				t.Fatalf("stage %s status %s, want NOT_TESTED: raw ingestion must not claim it", s, byStage[s].Status)
			}
		}
	})
}

// A connector that rejects the credentials is an ERROR stage. The attack stage downstream
// of it is NOT_TESTED, and nothing is dispatched for it.
func TestPipelineStage_RejectedConnectorBlocksDownstreamAsNotTested(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		es := fakeElastic(t, 401, `{}`)
		defer es.Close()
		insertElasticConnector(t, pool, "dc-pipe-bad", es.URL)
		def := pipelineCampaignDef("pipe-bad-1", "dc-pipe-bad", true)
		if err := (db.KillChainStore{Pool: pool}).CreateCampaign(context.Background(), def, "owner-1", ""); err != nil {
			t.Fatal(err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		if rec := advance(h, def.ID, ""); rec.Code != http.StatusOK {
			t.Fatalf("advance: status=%d body=%s", rec.Code, rec.Body.String())
		}
		rec, err := (db.KillChainStore{Pool: pool}).Campaign(context.Background(), def.ID)
		if err != nil {
			t.Fatal(err)
		}
		ingest := rec.Stages["ingest"]
		if ingest.Verdict != killchain.VerdictError || !strings.Contains(strings.Join(ingest.Reasons, " "), "rejected") {
			t.Fatalf("ingest verdict=%s reasons=%v, want ERROR naming the rejection", ingest.Verdict, ingest.Reasons)
		}
		if attack := rec.Stages["attack"]; attack.Verdict != killchain.VerdictNotTested {
			t.Fatalf("attack verdict=%s, want NOT_TESTED behind an errored pipeline stage", attack.Verdict)
		}
	})
}

// A connector id that does not exist is an ERROR stage, never an empty pass.
func TestPipelineStage_UnknownConnectorIsError(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		def := pipelineCampaignDef("pipe-missing-1", "dc-does-not-exist", false)
		if err := (db.KillChainStore{Pool: pool}).CreateCampaign(context.Background(), def, "owner-1", ""); err != nil {
			t.Fatal(err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		advance(h, def.ID, "")
		rec, err := (db.KillChainStore{Pool: pool}).Campaign(context.Background(), def.ID)
		if err != nil {
			t.Fatal(err)
		}
		if v := rec.Stages["ingest"].Verdict; v != killchain.VerdictError {
			t.Fatalf("verdict=%s, want ERROR for a missing connector", v)
		}
	})
}

// pipelinePersistStages is the stage list a pipeline result must cover, in pipeline order.
func pipelinePersistStages() []string {
	return []string{"connectivity", "ingestion", "normalization", "correlation", "alert", "case", "routing", "acknowledgement", "escalation"}
}

// A completed pipeline check survives a restart. The stage is left dispatched, as if the
// process stopped after dispatch, and the connector is then unreachable. Recovery must read the
// persisted result and must not run the check again.
func TestPipelineStage_CompletedResultSurvivesRestart(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		es := fakeElastic(t, 200, `{"hits":{"total":{"value":1,"relation":"eq"},"hits":[
		  {"_id":"doc-1","_source":{"@timestamp":"2026-10-20T09:02:03Z"}}]}}`)
		insertElasticConnector(t, pool, "dc-restart", es.URL)
		def := pipelineCampaignDef("pipe-restart-1", "dc-restart", false)
		store := db.KillChainStore{Pool: pool}
		if err := store.CreateCampaign(context.Background(), def, "owner-1", ""); err != nil {
			t.Fatal(err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		if rec := advance(h, def.ID, ""); rec.Code != http.StatusOK {
			t.Fatalf("advance: status=%d body=%s", rec.Code, rec.Body.String())
		}
		done, err := store.Campaign(context.Background(), def.ID)
		if err != nil {
			t.Fatal(err)
		}
		first := done.Stages["ingest"]

		// Simulate the crash: the stage is back to dispatched, and the connector is gone.
		if err := store.PutStage(context.Background(), def.ID, killchain.StageRecord{
			Key: "ingest", State: killchain.StateDispatched, ExecutionID: first.ExecutionID}); err != nil {
			t.Fatal(err)
		}
		es.Close()

		if err := RecoverKillChainCampaigns(context.Background(), pool, nil); err != nil {
			t.Fatalf("recover: %v", err)
		}
		after, err := store.Campaign(context.Background(), def.ID)
		if err != nil {
			t.Fatal(err)
		}
		got := after.Stages["ingest"]
		if got.Verdict != killchain.VerdictInconclusive || got.State != killchain.StateCompleted {
			t.Fatalf("after restart verdict=%s state=%s reasons=%v, want the persisted INCONCLUSIVE",
				got.Verdict, got.State, got.Reasons)
		}
		if len(got.Evidence.Pipeline) != len(pipelinePersistStages()) {
			t.Fatalf("persisted evidence lost across restart: %d stages", len(got.Evidence.Pipeline))
		}
	})
}

// A check that started but never completed before a restart is an unknown outcome: it is
// marked interrupted, never ERROR and never a pass.
func TestPipelineStage_IncompleteCheckIsInterruptedNotError(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		def := pipelineCampaignDef("pipe-incomplete-1", "dc-unused", false)
		store := db.KillChainStore{Pool: pool}
		if err := store.CreateCampaign(context.Background(), def, "owner-1", ""); err != nil {
			t.Fatal(err)
		}
		execID := pipelineExecutionID(def.ID, "ingest")
		if err := store.BeginPipelineRun(context.Background(), db.PipelineRun{ExecutionID: execID,
			CampaignID: def.ID, StageKey: "ingest", ConnectorID: "dc-unused", StartedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if err := store.PutStage(context.Background(), def.ID, killchain.StageRecord{
			Key: "ingest", State: killchain.StateDispatched, ExecutionID: execID}); err != nil {
			t.Fatal(err)
		}
		if err := RecoverKillChainCampaigns(context.Background(), pool, nil); err != nil {
			t.Fatalf("recover: %v", err)
		}
		after, err := store.Campaign(context.Background(), def.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got := after.Stages["ingest"]; got.State != killchain.StateInterrupted || got.Verdict == killchain.VerdictError {
			t.Fatalf("state=%s verdict=%s, want interrupted and not ERROR", got.State, got.Verdict)
		}
	})
}
