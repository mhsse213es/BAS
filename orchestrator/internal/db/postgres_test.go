package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

// EnsureSchema must be safe to call repeatedly (startup runs it every boot)
// and must create the agent_certificates table for B1/B3 mTLS certificate tracking.
func TestEnsureSchema_CreatesAgentCertificatesTable(t *testing.T) {
	ctx := context.Background()
	if err := db.EnsureSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatalf("first EnsureSchema: %v", err)
	}
	if err := db.EnsureSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatalf("second EnsureSchema (idempotency): %v", err)
	}

	var exists bool
	err := sharedDB.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_certificates')`,
	).Scan(&exists)
	if err != nil {
		t.Fatalf("query information_schema: %v", err)
	}
	if !exists {
		t.Fatal("agent_certificates table was not created")
	}
}
