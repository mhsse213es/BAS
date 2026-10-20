package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/killchain"
)

// ErrKillChainNotFound is returned when a campaign id does not exist.
var ErrKillChainNotFound = errors.New("killchain campaign not found")

// EnsureKillChainSchema creates the kill-chain tables. It is idempotent, so it
// can run at every boot. Stage edges live inside the stored definition rather
// than in a separate table: a definition is authored and versioned as one
// document, so splitting it would only create a second place for it to drift.
// No tenant_id column, matching the other run tables (see phishing_runs).
func EnsureKillChainSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS killchain_campaigns (
			id          text        PRIMARY KEY,
			name        text        NOT NULL DEFAULT '',
			version     int         NOT NULL,
			definition  jsonb       NOT NULL,
			created_by  text        NOT NULL DEFAULT '',
			created_at  timestamptz NOT NULL DEFAULT NOW()
		);
		ALTER TABLE killchain_campaigns ADD COLUMN IF NOT EXISTS agent_id text NOT NULL DEFAULT '';
		CREATE TABLE IF NOT EXISTS killchain_stages (
			campaign_id  text        NOT NULL REFERENCES killchain_campaigns(id),
			stage_key    text        NOT NULL,
			state        text        NOT NULL,
			verdict      text        NOT NULL DEFAULT '',
			reasons      jsonb       NOT NULL DEFAULT '[]',
			execution_id text        NOT NULL DEFAULT '',
			evidence     jsonb,
			updated_at   timestamptz NOT NULL DEFAULT NOW(),
			PRIMARY KEY (campaign_id, stage_key)
		);
		CREATE TABLE IF NOT EXISTS killchain_ground_truth (
			run_id      text        PRIMARY KEY,
			source      text        NOT NULL,
			executed    text        NOT NULL,
			reference   text        NOT NULL,
			recorded_by text        NOT NULL DEFAULT '',
			recorded_at timestamptz NOT NULL DEFAULT NOW()
		);
		ALTER TABLE killchain_ground_truth ADD COLUMN IF NOT EXISTS source_class text NOT NULL DEFAULT '';
		CREATE TABLE IF NOT EXISTS killchain_host_events (
			run_id       text        NOT NULL,
			record_id    bigint      NOT NULL,
			event_id     int         NOT NULL,
			host         text        NOT NULL,
			ts           timestamptz NOT NULL,
			subject      text        NOT NULL DEFAULT '',
			new_process  text        NOT NULL DEFAULT '',
			command_line text        NOT NULL DEFAULT '',
			logon_type   int         NOT NULL DEFAULT 0,
			target_user  text        NOT NULL DEFAULT '',
			received_at  timestamptz NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS killchain_host_events_run ON killchain_host_events (run_id);
		CREATE TABLE IF NOT EXISTS killchain_run_audit (
			run_id           text        PRIMARY KEY,
			process_creation text        NOT NULL,
			logon            text        NOT NULL,
			received_at      timestamptz NOT NULL DEFAULT NOW()
		);
		ALTER TABLE killchain_run_audit ADD COLUMN IF NOT EXISTS command_line text NOT NULL DEFAULT '';
		ALTER TABLE killchain_run_audit ADD COLUMN IF NOT EXISTS window_from timestamptz NOT NULL DEFAULT '1970-01-01T00:00:00Z';
		ALTER TABLE killchain_run_audit ADD COLUMN IF NOT EXISTS window_to timestamptz NOT NULL DEFAULT '1970-01-01T00:00:00Z';
		CREATE TABLE IF NOT EXISTS killchain_coverage_proofs (
			scenario_id     text        PRIMARY KEY,
			domain          text        NOT NULL DEFAULT '',
			platform        text        NOT NULL DEFAULT '',
			control         text        NOT NULL DEFAULT '',
			campaign        text        NOT NULL DEFAULT '',
			unsupported     boolean     NOT NULL DEFAULT false,
			fixture_test_id text        NOT NULL DEFAULT '',
			adapter_test_id text        NOT NULL DEFAULT '',
			lab_run_id      text        NOT NULL DEFAULT '',
			live_run_id     text        NOT NULL DEFAULT '',
			recorded_by     text        NOT NULL DEFAULT '',
			recorded_at     timestamptz NOT NULL DEFAULT NOW()
		);
	`)
	if err != nil {
		return fmt.Errorf("ensure killchain schema: %w", err)
	}
	return nil
}

// KillChainStore persists kill-chain campaigns. It implements killchain.Store.
type KillChainStore struct {
	Pool *pgxpool.Pool
}

// CreateCampaign stores a validated definition and one pending row per stage.
// The definition must already pass Validate.
func (s KillChainStore) CreateCampaign(ctx context.Context, def killchain.CampaignDef, createdBy, agentID string) error {
	raw, err := json.Marshal(def)
	if err != nil {
		return fmt.Errorf("marshal campaign: %w", err)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO killchain_campaigns (id, name, version, definition, created_by, agent_id)
		VALUES ($1, $2, $3, $4, $5, $6)`, def.ID, def.Name, def.Version, raw, createdBy, agentID); err != nil {
		return fmt.Errorf("insert campaign: %w", err)
	}
	for _, st := range def.Stages {
		if _, err := tx.Exec(ctx, `INSERT INTO killchain_stages (campaign_id, stage_key, state)
			VALUES ($1, $2, $3)`, def.ID, st.Key, string(killchain.StatePending)); err != nil {
			return fmt.Errorf("insert stage %s: %w", st.Key, err)
		}
	}
	return tx.Commit(ctx)
}

// Campaign loads a campaign's definition and every stage record.
func (s KillChainStore) Campaign(ctx context.Context, id string) (killchain.CampaignRecord, error) {
	var raw []byte
	var agentID string
	err := s.Pool.QueryRow(ctx, `SELECT definition, agent_id FROM killchain_campaigns WHERE id = $1`, id).Scan(&raw, &agentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return killchain.CampaignRecord{}, ErrKillChainNotFound
	}
	if err != nil {
		return killchain.CampaignRecord{}, err
	}
	var def killchain.CampaignDef
	if err := json.Unmarshal(raw, &def); err != nil {
		return killchain.CampaignRecord{}, fmt.Errorf("decode campaign definition: %w", err)
	}

	rows, err := s.Pool.Query(ctx, `SELECT stage_key, state, verdict, reasons, execution_id, evidence
		FROM killchain_stages WHERE campaign_id = $1`, id)
	if err != nil {
		return killchain.CampaignRecord{}, err
	}
	defer rows.Close()
	stages := map[string]killchain.StageRecord{}
	for rows.Next() {
		var (
			sr         killchain.StageRecord
			state      string
			verdict    string
			reasonsRaw []byte
			evRaw      []byte
		)
		if err := rows.Scan(&sr.Key, &state, &verdict, &reasonsRaw, &sr.ExecutionID, &evRaw); err != nil {
			return killchain.CampaignRecord{}, err
		}
		sr.State = killchain.StageState(state)
		sr.Verdict = killchain.Verdict(verdict)
		if len(reasonsRaw) > 0 {
			if err := json.Unmarshal(reasonsRaw, &sr.Reasons); err != nil {
				return killchain.CampaignRecord{}, fmt.Errorf("decode reasons for %s: %w", sr.Key, err)
			}
		}
		if len(evRaw) > 0 {
			var ev killchain.StageEvidence
			if err := json.Unmarshal(evRaw, &ev); err != nil {
				return killchain.CampaignRecord{}, fmt.Errorf("decode evidence for %s: %w", sr.Key, err)
			}
			sr.Evidence = &ev
		}
		stages[sr.Key] = sr
	}
	if err := rows.Err(); err != nil {
		return killchain.CampaignRecord{}, err
	}
	return killchain.CampaignRecord{ID: id, Def: def, AgentID: agentID, Stages: stages}, nil
}

// PutStage writes one stage record in full. It is idempotent for the same record.
func (s KillChainStore) PutStage(ctx context.Context, campaignID string, rec killchain.StageRecord) error {
	reasons, err := json.Marshal(rec.Reasons)
	if err != nil {
		return err
	}
	var evidence []byte
	if rec.Evidence != nil {
		evidence, err = json.Marshal(rec.Evidence)
		if err != nil {
			return err
		}
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO killchain_stages
		(campaign_id, stage_key, state, verdict, reasons, execution_id, evidence, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (campaign_id, stage_key) DO UPDATE SET
			state = EXCLUDED.state, verdict = EXCLUDED.verdict, reasons = EXCLUDED.reasons,
			execution_id = EXCLUDED.execution_id, evidence = EXCLUDED.evidence, updated_at = EXCLUDED.updated_at`,
		campaignID, rec.Key, string(rec.State), string(rec.Verdict), reasons, rec.ExecutionID, evidence, time.Now().UTC())
	return err
}

// KillChainCampaignSummary is one row of the campaign list.
type KillChainCampaignSummary struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
}

// ListCampaigns returns campaigns, newest first.
func (s KillChainStore) ListCampaigns(ctx context.Context) ([]KillChainCampaignSummary, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, name, version, created_by, created_at
		FROM killchain_campaigns ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KillChainCampaignSummary{}
	for rows.Next() {
		var c KillChainCampaignSummary
		if err := rows.Scan(&c.ID, &c.Name, &c.Version, &c.CreatedBy, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
