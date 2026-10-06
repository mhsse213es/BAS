package main

import (
	"context"
	"fmt"
	"io"

	"github.com/audspect/bas/config"
	"github.com/audspect/bas/internal/db/migrate"
)

const migrateUsage = "usage: orchestrator migrate up|status|rotate-app-password"

// runMigrateCmd runs `orchestrator migrate <sub>` (H1) as the schema owner
// (DATABASE_ADMIN_URL). Exit codes: 0 ok; 1 error; 2 `status` with pending work.
func runMigrateCmd(args []string, cfg *config.Config, out io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(out, migrateUsage)
		return 1
	}
	sub := args[0]
	switch sub {
	case "up", "status", "rotate-app-password":
	default:
		fmt.Fprintf(out, "unknown migrate subcommand %q\n%s\n", sub, migrateUsage)
		return 1
	}
	if cfg.DatabaseAdminURL == "" {
		fmt.Fprintln(out, "migrate: DATABASE_ADMIN_URL is required (schema-owner connection)")
		return 1
	}
	if sub != "status" && cfg.AppDBPassword == "" {
		fmt.Fprintln(out, "migrate: BAS_APP_DB_PASSWORD is required")
		return 1
	}
	ctx := context.Background()
	fail := func(err error) int {
		fmt.Fprintf(out, "migrate %s: %v\n", sub, err)
		return 1
	}
	switch sub {
	case "up":
		r, err := migrate.Up(ctx, cfg.DatabaseAdminURL, migrate.Options{AppPassword: cfg.AppDBPassword, Out: out})
		if err != nil {
			return fail(err)
		}
		fmt.Fprintln(out, "migrate up: "+r.Summary())
		for _, o := range r.Extra {
			fmt.Fprintf(out, "migrate up: kept object outside the baseline: %s/%s (recorded in h1_adoption_report)\n", o.Kind, o.Name)
		}
	case "status":
		st, err := migrate.GetStatus(ctx, cfg.DatabaseAdminURL)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(out, "schema %d (latest %d), dirty=%t, reference data %d (latest %d), pending=%t\n",
			st.Version, st.WantVersion, st.Dirty, st.Seed, st.WantSeed, st.Pending)
		if st.Pending {
			return 2
		}
	case "rotate-app-password":
		if err := migrate.RotateAppPassword(ctx, cfg.DatabaseAdminURL, cfg.AppDBPassword); err != nil {
			return fail(err)
		}
		fmt.Fprintln(out, "migrate rotate-app-password: bas_app password updated and verified")
	}
	return 0
}
