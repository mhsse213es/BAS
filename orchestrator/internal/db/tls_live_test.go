package db

import (
	"context"
	"os"
	"testing"
)

// TestConnect_VerifiedTLSAgainstLivePostgres checks the real handshake against a
// Postgres that serves the installer's certificate. It is skipped unless the
// operator points it at a running server:
//
//	BAS_DB_TLS_TEST_DSN          verify-full DSN with a correct sslrootcert; must connect
//	BAS_DB_TLS_TEST_WRONG_CA_DSN verify-full DSN whose sslrootcert is another CA; must fail
//	BAS_DB_TLS_TEST_BAD_HOST_DSN verify-full DSN to an address not in the certificate SAN; must fail
func TestConnect_VerifiedTLSAgainstLivePostgres(t *testing.T) {
	good := os.Getenv("BAS_DB_TLS_TEST_DSN")
	if good == "" {
		t.Skip("BAS_DB_TLS_TEST_DSN not set; needs a TLS Postgres from db-tls.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20e9)
	defer cancel()

	pool, err := Connect(ctx, good)
	if err != nil {
		t.Fatalf("verified connection failed: %v", err)
	}
	defer pool.Close()

	var ssl bool
	if err := pool.QueryRow(ctx, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&ssl); err != nil {
		t.Fatalf("pg_stat_ssl: %v", err)
	}
	if !ssl {
		t.Fatal("connection is not encrypted")
	}

	if wrong := os.Getenv("BAS_DB_TLS_TEST_WRONG_CA_DSN"); wrong != "" {
		if p, err := Connect(ctx, wrong); err == nil {
			p.Close()
			t.Fatal("a certificate from another CA was accepted")
		}
	}
	if bad := os.Getenv("BAS_DB_TLS_TEST_BAD_HOST_DSN"); bad != "" {
		if p, err := Connect(ctx, bad); err == nil {
			p.Close()
			t.Fatal("a hostname outside the certificate SAN was accepted")
		}
	}
}
