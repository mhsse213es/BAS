// Package store persists Aleef engagements, runs, generated tests, execution
// results and findings. Findings move candidate -> verified only through
// MarkVerified with an evidence hash; every state change is appended to an
// append-only history table enforced by database triggers.
package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureSchema creates the Aleef tables idempotently.
func EnsureSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS aleef_engagements (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			customer       text        NOT NULL,
			environment    text        NOT NULL,
			approved_hosts text[]      NOT NULL DEFAULT '{}',
			engagement_window text        NOT NULL DEFAULT '',
			approver       text        NOT NULL DEFAULT '',
			body           jsonb       NOT NULL DEFAULT '{}',
			created_at     timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS aleef_runs (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			engagement_id text        REFERENCES aleef_engagements(id),
			created_at    timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS aleef_tests (
			run_id   text    NOT NULL REFERENCES aleef_runs(id) ON DELETE CASCADE,
			id       text    NOT NULL,
			property text    NOT NULL,
			params   jsonb   NOT NULL DEFAULT '{}',
			scenario jsonb   NOT NULL DEFAULT '{}',
			covered  boolean NOT NULL DEFAULT false,
			PRIMARY KEY (run_id, id)
		)`,
		`CREATE TABLE IF NOT EXISTS aleef_results (
			run_id          text        NOT NULL,
			test_id         text        NOT NULL,
			exec_no         integer     NOT NULL CHECK (exec_no > 0),
			report          jsonb       NOT NULL,
			verdict_finding text        NOT NULL CHECK (verdict_finding IN ('yes', 'no', 'inconclusive')),
			verdict_reason  text        NOT NULL DEFAULT '',
			verdict_oracle  text        NOT NULL DEFAULT '',
			started_at      timestamptz NOT NULL DEFAULT NOW(),
			PRIMARY KEY (run_id, test_id, exec_no),
			FOREIGN KEY (run_id, test_id) REFERENCES aleef_tests(run_id, id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS aleef_findings (
			id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			run_id          text        NOT NULL,
			test_id         text        NOT NULL,
			property        text        NOT NULL,
			state           text        NOT NULL DEFAULT 'candidate'
				CHECK (state IN ('candidate', 'verified', 'rejected', 'unconfirmed')),
			prior_knowledge text        NOT NULL DEFAULT 'not_checked'
				CHECK (prior_knowledge IN ('not_checked', 'checked_none_found', 'known_public', 'known_vendor')),
			evidence_hash   text,
			covered         boolean     NOT NULL DEFAULT false,
			created_at      timestamptz NOT NULL DEFAULT NOW(),
			updated_at      timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (run_id, test_id),
			FOREIGN KEY (run_id, test_id) REFERENCES aleef_tests(run_id, id) ON DELETE CASCADE,
			CONSTRAINT aleef_findings_verified_needs_hash
				CHECK (state <> 'verified' OR (evidence_hash IS NOT NULL AND evidence_hash <> ''))
		)`,
		`CREATE INDEX IF NOT EXISTS aleef_findings_run_state_idx ON aleef_findings (run_id, state)`,
		`CREATE TABLE IF NOT EXISTS aleef_finding_history (
			id             bigserial   PRIMARY KEY,
			finding_id     text        NOT NULL REFERENCES aleef_findings(id) ON DELETE CASCADE,
			previous_state text        NOT NULL DEFAULT '',
			new_state      text        NOT NULL,
			reason         text        NOT NULL DEFAULT '',
			actor          text        NOT NULL DEFAULT '',
			at             timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS aleef_finding_history_finding_idx ON aleef_finding_history (finding_id, id)`,
		// History is append-only: UPDATE and DELETE are rejected. A cascade
		// from deleting a finding is likewise refused, so findings with
		// history cannot be deleted.
		`CREATE OR REPLACE FUNCTION aleef_history_append_only() RETURNS trigger AS $$
		BEGIN
			RAISE EXCEPTION 'aleef_finding_history is append-only';
		END;
		$$ LANGUAGE plpgsql`,
		`DROP TRIGGER IF EXISTS aleef_finding_history_append_only ON aleef_finding_history`,
		`CREATE TRIGGER aleef_finding_history_append_only
			BEFORE UPDATE OR DELETE ON aleef_finding_history
			FOR EACH ROW EXECUTE FUNCTION aleef_history_append_only()`,
		// A verified finding never returns to candidate.
		`CREATE OR REPLACE FUNCTION aleef_no_verified_regress() RETURNS trigger AS $$
		BEGIN
			IF OLD.state = 'verified' AND NEW.state = 'candidate' THEN
				RAISE EXCEPTION 'a verified finding cannot return to candidate';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql`,
		`DROP TRIGGER IF EXISTS aleef_findings_no_regress ON aleef_findings`,
		`CREATE TRIGGER aleef_findings_no_regress
			BEFORE UPDATE ON aleef_findings
			FOR EACH ROW EXECUTE FUNCTION aleef_no_verified_regress()`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return err
		}
	}
	return nil
}
