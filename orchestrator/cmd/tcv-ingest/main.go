// Command tcv-ingest records bundle_packaged events for a bundle manifest
// written by packaging/bundle-manifest.sh. It runs where the BAS database is,
// after the build, and never runs on the build host.
//
// Usage:
//
//	DATABASE_URL=postgres://... tcv-ingest -manifest dist/<bundle>/bundle-manifest.json
//
// Exit codes: 0 on success (including when some hashes have no registry
// match, which is reported, not failed), 1 on an unreadable or invalid
// manifest or a database failure, 2 on bad usage.
//
// It assumes the server has booted at least once against this database, so
// the tcf_pipeline_events table and its CHECK migration already exist. The
// command does not run migrations itself.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/audspect/bas/internal/tcv"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout))
}

// run is the testable core. getenv is injected so tests control DATABASE_URL.
func run(args []string, getenv func(string) string, out io.Writer) int {
	fs := flag.NewFlagSet("tcv-ingest", flag.ContinueOnError)
	fs.SetOutput(out)
	manifestPath := fs.String("manifest", "", "path to bundle-manifest.json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *manifestPath == "" {
		fmt.Fprintln(out, "usage: tcv-ingest -manifest <bundle-manifest.json>  (requires DATABASE_URL)")
		return 2
	}

	raw, err := os.ReadFile(*manifestPath)
	if err != nil {
		fmt.Fprintf(out, "tcv-ingest: read manifest: %v\n", err)
		return 1
	}
	var m tcv.BundleManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		fmt.Fprintf(out, "tcv-ingest: parse manifest: %v\n", err)
		return 1
	}
	if err := m.Validate(); err != nil {
		fmt.Fprintf(out, "tcv-ingest: %v\n", err)
		return 1
	}

	dsn := getenv("DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(out, "tcv-ingest: DATABASE_URL is required")
		return 1
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintf(out, "tcv-ingest: connect: %v\n", err)
		return 1
	}
	defer pool.Close()

	recorded, unmatched, err := tcv.IngestBundleManifest(ctx, pool, tcv.DBVersionLookup(pool), m)
	if err != nil {
		fmt.Fprintf(out, "tcv-ingest: ingest: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "tcv-ingest: bundle=%s recorded=%d unmatched=%d\n", m.BundleID, recorded, len(unmatched))
	return 0
}
