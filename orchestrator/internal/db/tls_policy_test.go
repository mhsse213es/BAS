package db

import "testing"

// Database connections must verify the server certificate. A DSN that asks for
// anything weaker is refused at startup, before any traffic is sent.
func TestRequireVerifiedDBTLS(t *testing.T) {
	const root = "&sslrootcert=/etc/audspect/dbtls/server.crt"
	cases := []struct {
		name    string
		dsn     string
		devOK   bool
		wantErr bool
	}{
		{"disable is refused", "postgres://u:p@postgres:5432/db?sslmode=disable" + root, false, true},
		{"prefer is refused", "postgres://u:p@postgres:5432/db?sslmode=prefer" + root, false, true},
		{"require is refused (no hostname check)", "postgres://u:p@postgres:5432/db?sslmode=require" + root, false, true},
		{"verify-ca is refused (no hostname check)", "postgres://u:p@postgres:5432/db?sslmode=verify-ca" + root, false, true},
		{"verify-full without a root certificate is refused", "postgres://u:p@postgres:5432/db?sslmode=verify-full", false, true},
		{"verify-full with a root certificate is accepted", "postgres://u:p@postgres:5432/db?sslmode=verify-full" + root, false, false},
		{"missing sslmode is refused", "postgres://u:p@postgres:5432/db" + root, false, true},
		{"dev override allows prefer", "postgres://u:p@postgres:5432/db?sslmode=prefer", true, false},
		{"dev override does not allow a missing DSN", "", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := RequireVerifiedDBTLS(c.dsn, c.devOK)
			if (err != nil) != c.wantErr {
				t.Fatalf("RequireVerifiedDBTLS(%q, %v) = %v; wantErr %v", c.dsn, c.devOK, err, c.wantErr)
			}
		})
	}
}
