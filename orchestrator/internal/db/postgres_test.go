package db_test

import (
	"context"
	"testing"
)

// The migrated schema has the agent_certificates table for B1/B3 mTLS
// certificate tracking.
func TestSchema_AgentCertificatesTable(t *testing.T) {
	ctx := context.Background()

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
