package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/emailgwcampaign"
)

// EnsureEmailGWCampaignSchema creates email_gw_campaigns and
// email_gw_campaign_stages, and adds email_gw_runs.campaign_id --
// mirroring cloud_runs.campaign_id exactly, so a stage's own run row
// is the single source of evidence; the stage row itself never copies
// a result. Must run after EnsureEmailGWRunSchema (email_gw_runs must
// already exist for the ALTER/index below).
func EnsureEmailGWCampaignSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS email_gw_campaigns (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			template_id   text        NOT NULL,
			status        text        NOT NULL DEFAULT 'running',
			initiated_by  text        NOT NULL DEFAULT '',
			created_at    timestamptz NOT NULL DEFAULT NOW(),
			completed_at  timestamptz,
			CONSTRAINT email_gw_campaigns_status_check
				CHECK (status IN ('running','completed','partial','failed','cancelling','cancelled'))
		)`)
	if err != nil {
		return fmt.Errorf("email_gw_campaigns: ensure schema: %w", err)
	}

	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS email_gw_campaign_stages (
			id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			campaign_id     text        NOT NULL REFERENCES email_gw_campaigns(id),
			ordinal         int         NOT NULL,
			stage_key       text        NOT NULL,
			run_id          text        REFERENCES email_gw_runs(id),
			status          text        NOT NULL DEFAULT 'pending',
			blocked_reason  text        NOT NULL DEFAULT '',
			created_at      timestamptz NOT NULL DEFAULT NOW(),
			completed_at    timestamptz,
			CONSTRAINT email_gw_campaign_stages_status_check
				CHECK (status IN ('pending','dispatched','completed','blocked_by_prerequisite','failed','cancelled')),
			CONSTRAINT email_gw_campaign_stages_unique_ordinal UNIQUE (campaign_id, ordinal)
		)`)
	if err != nil {
		return fmt.Errorf("email_gw_campaign_stages: ensure schema: %w", err)
	}
	if _, err := pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_email_gw_campaign_stages_campaign ON email_gw_campaign_stages (campaign_id)`); err != nil {
		return fmt.Errorf("email_gw_campaign_stages: create campaign index: %w", err)
	}
	if _, err := pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_email_gw_campaign_stages_dispatched ON email_gw_campaign_stages (status) WHERE status = 'dispatched'`); err != nil {
		return fmt.Errorf("email_gw_campaign_stages: create dispatched index: %w", err)
	}

	if _, err := pool.Exec(ctx, `ALTER TABLE email_gw_runs ADD COLUMN IF NOT EXISTS campaign_id text`); err != nil {
		return fmt.Errorf("email_gw_runs: add campaign_id: %w", err)
	}
	if _, err := pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_email_gw_runs_campaign ON email_gw_runs (campaign_id) WHERE campaign_id IS NOT NULL`); err != nil {
		return fmt.Errorf("email_gw_runs: create campaign index: %w", err)
	}
	return nil
}

// InsertEmailGWCampaign writes a new email_gw_campaigns row. The
// caller supplies c.ID and c.Status already set.
func InsertEmailGWCampaign(ctx context.Context, pool *pgxpool.Pool, c *emailgwcampaign.Campaign) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO email_gw_campaigns (id, template_id, status, initiated_by, created_at, completed_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		c.ID, c.TemplateID, string(c.Status), c.InitiatedBy, c.CreatedAt, c.CompletedAt)
	if err != nil {
		return fmt.Errorf("email_gw_campaigns: insert %s: %w", c.ID, err)
	}
	return nil
}

const emailGWCampaignColumns = `id, template_id, status, initiated_by, created_at, completed_at`

func scanEmailGWCampaign(row pgx.Row) (*emailgwcampaign.Campaign, error) {
	c := &emailgwcampaign.Campaign{}
	var status string
	if err := row.Scan(&c.ID, &c.TemplateID, &status, &c.InitiatedBy, &c.CreatedAt, &c.CompletedAt); err != nil {
		return nil, err
	}
	c.Status = emailgwcampaign.CampaignStatus(status)
	return c, nil
}

// GetEmailGWCampaign returns one email_gw_campaigns row by id.
func GetEmailGWCampaign(ctx context.Context, pool *pgxpool.Pool, id string) (*emailgwcampaign.Campaign, error) {
	row := pool.QueryRow(ctx, `SELECT `+emailGWCampaignColumns+` FROM email_gw_campaigns WHERE id = $1`, id)
	c, err := scanEmailGWCampaign(row)
	if err != nil {
		return nil, fmt.Errorf("email_gw_campaigns: get %s: %w", id, err)
	}
	return c, nil
}

// ListEmailGWCampaigns returns up to limit campaigns, newest first.
func ListEmailGWCampaigns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*emailgwcampaign.Campaign, error) {
	rows, err := pool.Query(ctx, `SELECT `+emailGWCampaignColumns+` FROM email_gw_campaigns ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("email_gw_campaigns: list: %w", err)
	}
	defer rows.Close()
	var out []*emailgwcampaign.Campaign
	for rows.Next() {
		c, err := scanEmailGWCampaign(rows)
		if err != nil {
			return nil, fmt.Errorf("email_gw_campaigns: list scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("email_gw_campaigns: list rows: %w", err)
	}
	return out, nil
}

// UpdateEmailGWCampaignStatus transitions a campaign's own status.
// completedAt is written only when non-zero.
func UpdateEmailGWCampaignStatus(ctx context.Context, pool *pgxpool.Pool, id string, status emailgwcampaign.CampaignStatus, completedAt time.Time) error {
	var completedAtArg any
	if !completedAt.IsZero() {
		completedAtArg = completedAt
	}
	_, err := pool.Exec(ctx, `UPDATE email_gw_campaigns SET status = $1, completed_at = COALESCE($2, completed_at) WHERE id = $3`,
		string(status), completedAtArg, id)
	if err != nil {
		return fmt.Errorf("email_gw_campaigns: update status for %s: %w", id, err)
	}
	return nil
}

// InsertEmailGWCampaignStage writes a new email_gw_campaign_stages
// row. Returns isUniqueViolation-detectable errors verbatim (never
// wrapped into a generic message) so the caller can treat a
// duplicate-ordinal insert -- the race RecoverEmailGWCampaigns and a
// still-live continuation goroutine can both hit -- as a benign
// "already advanced" no-op rather than a real failure.
func InsertEmailGWCampaignStage(ctx context.Context, pool *pgxpool.Pool, s *emailgwcampaign.CampaignStage) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO email_gw_campaign_stages (id, campaign_id, ordinal, stage_key, run_id, status, blocked_reason, created_at, completed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		s.ID, s.CampaignID, s.Ordinal, s.StageKey, s.RunID, string(s.Status), s.BlockedReason, s.CreatedAt, s.CompletedAt)
	if err != nil {
		return err
	}
	return nil
}

const emailGWCampaignStageColumns = `id, campaign_id, ordinal, stage_key, run_id, status, blocked_reason, created_at, completed_at`

func scanEmailGWCampaignStage(row pgx.Row) (*emailgwcampaign.CampaignStage, error) {
	s := &emailgwcampaign.CampaignStage{}
	var status string
	if err := row.Scan(&s.ID, &s.CampaignID, &s.Ordinal, &s.StageKey, &s.RunID, &status, &s.BlockedReason, &s.CreatedAt, &s.CompletedAt); err != nil {
		return nil, err
	}
	s.Status = emailgwcampaign.StageStatus(status)
	return s, nil
}

// GetEmailGWCampaignStage returns one stage row by id.
func GetEmailGWCampaignStage(ctx context.Context, pool *pgxpool.Pool, id string) (*emailgwcampaign.CampaignStage, error) {
	row := pool.QueryRow(ctx, `SELECT `+emailGWCampaignStageColumns+` FROM email_gw_campaign_stages WHERE id = $1`, id)
	s, err := scanEmailGWCampaignStage(row)
	if err != nil {
		return nil, fmt.Errorf("email_gw_campaign_stages: get %s: %w", id, err)
	}
	return s, nil
}

// GetEmailGWCampaignStageByRunID returns the stage whose run_id is
// runID, or pgx.ErrNoRows if runID isn't a campaign stage's run (the
// common case -- most email_gw_runs rows are standalone, not part of
// any campaign). The run-completion continuation hook uses this to
// decide, cheaply, whether a just-finished run belongs to a campaign
// at all.
func GetEmailGWCampaignStageByRunID(ctx context.Context, pool *pgxpool.Pool, runID string) (*emailgwcampaign.CampaignStage, error) {
	row := pool.QueryRow(ctx, `SELECT `+emailGWCampaignStageColumns+` FROM email_gw_campaign_stages WHERE run_id = $1`, runID)
	s, err := scanEmailGWCampaignStage(row)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ListEmailGWCampaignStages returns every stage of campaignID,
// ordered by ordinal.
func ListEmailGWCampaignStages(ctx context.Context, pool *pgxpool.Pool, campaignID string) ([]*emailgwcampaign.CampaignStage, error) {
	rows, err := pool.Query(ctx, `SELECT `+emailGWCampaignStageColumns+` FROM email_gw_campaign_stages WHERE campaign_id = $1 ORDER BY ordinal ASC`, campaignID)
	if err != nil {
		return nil, fmt.Errorf("email_gw_campaign_stages: list %s: %w", campaignID, err)
	}
	defer rows.Close()
	var out []*emailgwcampaign.CampaignStage
	for rows.Next() {
		s, err := scanEmailGWCampaignStage(rows)
		if err != nil {
			return nil, fmt.Errorf("email_gw_campaign_stages: list scan: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("email_gw_campaign_stages: list rows: %w", err)
	}
	return out, nil
}

// UpdateEmailGWCampaignStageDispatched records that a
// StageKindInjected stage has a real run now, transitioning it to
// StageDispatched.
func UpdateEmailGWCampaignStageDispatched(ctx context.Context, pool *pgxpool.Pool, id, runID string) error {
	_, err := pool.Exec(ctx, `UPDATE email_gw_campaign_stages SET run_id = $1, status = $2 WHERE id = $3`,
		runID, string(emailgwcampaign.StageDispatched), id)
	if err != nil {
		return fmt.Errorf("email_gw_campaign_stages: update dispatched for %s: %w", id, err)
	}
	return nil
}

// UpdateEmailGWCampaignStageTerminal transitions a stage to a
// terminal status (completed/blocked_by_prerequisite/failed/cancelled),
// recording reason and completedAt. Used for every terminal
// transition except the initial dispatch.
func UpdateEmailGWCampaignStageTerminal(ctx context.Context, pool *pgxpool.Pool, id string, status emailgwcampaign.StageStatus, reason string, completedAt time.Time) error {
	_, err := pool.Exec(ctx, `UPDATE email_gw_campaign_stages SET status = $1, blocked_reason = $2, completed_at = $3 WHERE id = $4`,
		string(status), reason, completedAt, id)
	if err != nil {
		return fmt.Errorf("email_gw_campaign_stages: update terminal for %s: %w", id, err)
	}
	return nil
}

// ListDispatchedEmailGWCampaignStagesWithTerminalRuns returns every
// stage still sitting at StageDispatched whose own run has already
// reached a terminal email_gw_runs status -- the restart race
// RecoverEmailGWCampaigns exists to close: the process died after the
// run finished but before the continuation hook advanced the
// campaign.
func ListDispatchedEmailGWCampaignStagesWithTerminalRuns(ctx context.Context, pool *pgxpool.Pool) ([]*emailgwcampaign.CampaignStage, error) {
	rows, err := pool.Query(ctx, `
		SELECT s.id, s.campaign_id, s.ordinal, s.stage_key, s.run_id, s.status, s.blocked_reason, s.created_at, s.completed_at
		FROM email_gw_campaign_stages s
		JOIN email_gw_runs r ON r.id = s.run_id
		WHERE s.status = $1 AND r.status IN ('completed','partial','failed')`,
		string(emailgwcampaign.StageDispatched))
	if err != nil {
		return nil, fmt.Errorf("email_gw_campaign_stages: list dispatched-with-terminal-runs: %w", err)
	}
	defer rows.Close()
	var out []*emailgwcampaign.CampaignStage
	for rows.Next() {
		s, err := scanEmailGWCampaignStage(rows)
		if err != nil {
			return nil, fmt.Errorf("email_gw_campaign_stages: list dispatched-with-terminal-runs scan: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("email_gw_campaign_stages: list dispatched-with-terminal-runs rows: %w", err)
	}
	return out, nil
}

// emailGWCampaignStageColumnsPrefixed exists only so the JOIN query
// above can select s.id, s.campaign_id, ... without hand-duplicating
// emailGWCampaignStageColumns with an "s." prefix on every column.
func emailGWCampaignStageColumnsPrefixed() string {
	return "id, s.campaign_id, s.ordinal, s.stage_key, s.run_id, s.status, s.blocked_reason, s.created_at, s.completed_at"
}
