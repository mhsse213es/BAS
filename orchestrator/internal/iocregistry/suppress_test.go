package iocregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSetSuppressed_SetsFlagAndReason(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var id string
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO iocs (type, value, source) VALUES ('command_line', 'known-lab-tool', 'detection_alert') RETURNING id`).
			Scan(&id); err != nil {
			t.Fatalf("seed ioc: %v", err)
		}

		if err := SetSuppressed(context.Background(), pool, id, true, "known lab tool"); err != nil {
			t.Fatalf("SetSuppressed: %v", err)
		}

		var suppressed bool
		var reason string
		if err := pool.QueryRow(context.Background(),
			`SELECT suppressed, suppression_reason FROM iocs WHERE id = $1`, id).Scan(&suppressed, &reason); err != nil {
			t.Fatalf("query: %v", err)
		}
		if !suppressed || reason != "known lab tool" {
			t.Errorf("suppressed/reason = %v/%q, want true/\"known lab tool\"", suppressed, reason)
		}
	})
}

func TestSetSuppressed_UnsuppressClearsReasonRegardlessOfArgument(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var id string
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO iocs (type, value, source) VALUES ('command_line', 'previously-suppressed', 'detection_alert') RETURNING id`).
			Scan(&id); err != nil {
			t.Fatalf("seed ioc: %v", err)
		}
		if err := SetSuppressed(context.Background(), pool, id, true, "reason A"); err != nil {
			t.Fatalf("first SetSuppressed: %v", err)
		}

		// Unsuppressing with a non-empty reason argument still clears it --
		// a reason only makes sense while suppressed.
		if err := SetSuppressed(context.Background(), pool, id, false, "irrelevant text"); err != nil {
			t.Fatalf("second SetSuppressed: %v", err)
		}

		var suppressed bool
		var reason string
		if err := pool.QueryRow(context.Background(),
			`SELECT suppressed, suppression_reason FROM iocs WHERE id = $1`, id).Scan(&suppressed, &reason); err != nil {
			t.Fatalf("query: %v", err)
		}
		if suppressed || reason != "" {
			t.Errorf("suppressed/reason = %v/%q, want false/\"\"", suppressed, reason)
		}
	})
}
