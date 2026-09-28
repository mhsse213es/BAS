package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// checkSigningKeyNotSilentlyRotated is checkCANotSilentlyRotated's
// counterpart for the deployment command-signing key (main.go, this
// session's earlier B1/B3 work): a fresh key generation
// (signingKeyExistedBefore = false) on what turns out to be an EXISTING
// deployment -- evidence being an agent_certificates row that already
// recorded trust in a signing key -- must be refused rather than
// silently minting a new key no already-enrolled agent trusts, which
// would otherwise surface only as every dispatched command being
// inexplicably rejected agent-side with no indication why.
//
// signingKeyExistedBefore=true (the normal restart case: the key file
// was already on disk before LoadOrGenerateSigningKey ran) always skips
// this check, regardless of what's in agent_certificates.
//
// BAS_CONFIRM_NEW_SIGNING_KEY=true is the escape hatch for a genuine,
// intentional key rotation/reset -- distinctly named from B1/B3's
// BAS_CONFIRM_NEW_CA so an operator confirming one never accidentally
// confirms the other.
func checkSigningKeyNotSilentlyRotated(ctx context.Context, pool *pgxpool.Pool, signingKeyExistedBefore bool) error {
	if signingKeyExistedBefore {
		return nil
	}
	if os.Getenv("BAS_CONFIRM_NEW_SIGNING_KEY") == "true" {
		return nil
	}
	var count int
	err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM agent_certificates
		WHERE command_signing_key_id IS NOT NULL
		  AND revoked = false
		  AND expires_at > NOW()`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("check for existing command-signing trust: %w", err)
	}
	if count > 0 {
		return fmt.Errorf(
			"a command-signing key was just generated, but %d already-enrolled agent(s) recorded trust in a previous signing key -- "+
				"this looks like the ./signing directory was lost or reset on an EXISTING deployment, not a fresh install. "+
				"Every dispatched command would be silently rejected by agents still trusting the old key. "+
				"If this is intentional (a deliberate key rotation/reset), re-run with BAS_CONFIRM_NEW_SIGNING_KEY=true", count)
	}
	return nil
}
