// One-time H1 tool: builds a fresh database with the frozen legacy chain and
// writes internal/db/migrations/000001_baseline.{up,down}.sql from pg_dump.
// Kept for audit; not part of the server build.
//
// Usage (from orchestrator/, Docker running): go run ./tools/h1-capture-baseline
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/audspect/bas/internal/db/legacy"
	"github.com/audspect/bas/internal/db/schemacheck"
)

const out = "internal/db/migrations/"

func main() {
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("bas_platform"),
		tcpostgres.WithUsername("bas_user"),
		tcpostgres.WithPassword("bas_user"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		log.Fatalf("start postgres: %v", err)
	}
	defer func() { _ = c.Terminate(context.Background()) }()
	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	if err := legacy.EnsureAll(ctx, pool); err != nil {
		log.Fatalf("legacy chain: %v", err)
	}

	code, r, err := c.Exec(ctx, []string{"pg_dump", "-U", "bas_user", "--schema-only", "--no-owner", "--no-privileges", "--no-comments", "bas_platform"}, tcexec.Multiplexed())
	if err != nil || code != 0 {
		log.Fatalf("pg_dump: exit %d: %v", code, err)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	up, err := normalize(string(raw))
	if err != nil {
		log.Fatal(err)
	}
	header := "-- 000001 baseline, captured " + time.Now().UTC().Format("2006-01-02") +
		" by tools/h1-capture-baseline from internal/db/legacy (frozen).\n-- Never edit: schema changes are new migrations (README.md).\n\n"
	if err := os.WriteFile(out+"000001_baseline.up.sql", []byte(header+up), 0o644); err != nil {
		log.Fatal(err)
	}

	fp, err := schemacheck.Take(ctx, pool, "public")
	if err != nil {
		log.Fatal(err)
	}
	var tables, seqs, funcs []string
	for _, o := range fp {
		switch o.Kind {
		case "table":
			tables = append(tables, o.Name)
		case "sequence":
			seqs = append(seqs, o.Name)
		case "function":
			funcs = append(funcs, o.Name)
		}
	}
	sort.Strings(tables)
	sort.Strings(seqs)
	sort.Strings(funcs)
	var down bytes.Buffer
	down.WriteString("-- Development/test only. Production rollback is the upgrade snapshot (install.sh --rollback).\n\n")
	for _, t := range tables {
		fmt.Fprintf(&down, "DROP TABLE IF EXISTS %s CASCADE;\n", t)
	}
	for _, s := range seqs {
		fmt.Fprintf(&down, "DROP SEQUENCE IF EXISTS %s CASCADE;\n", s)
	}
	for _, f := range funcs {
		fmt.Fprintf(&down, "DROP FUNCTION IF EXISTS %s CASCADE;\n", f)
	}
	if err := os.WriteFile(out+"000001_baseline.down.sql", down.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s000001_baseline.{up,down}.sql: %d tables, %d sequences, %d functions\n", out, len(tables), len(seqs), len(funcs))
}

var (
	dropLine  = regexp.MustCompile(`^(SET |SELECT pg_catalog\.set_config|--|\\restrict|\\unrestrict)`)
	publicQ   = regexp.MustCompile(`\bpublic\.`)
	extension = regexp.MustCompile(`^CREATE EXTENSION IF NOT EXISTS (\w+) WITH SCHEMA public;$`)
	forbidden = regexp.MustCompile(`(?i)^(GRANT|REVOKE|ALTER DEFAULT PRIVILEGES|ALTER .* OWNER TO|COPY |INSERT )`)
)

// normalize turns pg_dump output into schema-relative baseline DDL.
func normalize(dump string) (string, error) {
	var b strings.Builder
	blank := false
	for _, l := range strings.Split(strings.ReplaceAll(dump, "\r\n", "\n"), "\n") {
		if dropLine.MatchString(l) {
			continue
		}
		if m := extension.FindStringSubmatch(l); m != nil {
			l = "CREATE EXTENSION IF NOT EXISTS " + m[1] + ";"
		}
		if forbidden.MatchString(l) {
			return "", fmt.Errorf("unexpected statement in schema-only dump: %q", l)
		}
		l = publicQ.ReplaceAllString(l, "")
		if strings.TrimSpace(l) == "" {
			if blank {
				continue
			}
			blank = true
		} else {
			blank = false
		}
		b.WriteString(l + "\n")
	}
	return strings.TrimLeft(b.String(), "\n"), nil
}
