package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/audspect/bas/internal/api"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/pki"
)

// rotationCheck reports how far the fleet is through the current rotation step. promote and retire consult it
// so the CA is never switched, or the old one dropped, ahead of the agents. nil means it cannot be checked.
type rotationCheck func(ctx context.Context, state pki.RotationState) (api.RotationReadiness, bool, error)

const skipReadinessFlag = "--skip-readiness-check"

// runCARotation drives a planned CA rotation from the command line (audit F-09), offline, against the PKI
// directory: `ca-rotation status|start|abort|promote|rollback|retire [--yes]`. Every step except status
// changes how the whole fleet is trusted, so it must be confirmed with --yes. promote and retire also refuse
// unless the fleet is ready (see rotationCheck), unless --skip-readiness-check is given. Steps take effect when the
// server next starts. Returns the process exit code.
func runCARotation(args []string, pkiDir string, out io.Writer, check rotationCheck) int {
	if len(args) == 0 {
		fmt.Fprintln(out, "usage: ca-rotation status|start|abort|promote|rollback|retire [--yes]")
		return 2
	}
	step := args[0]
	confirmed, skipCheck := false, false
	for _, a := range args[1:] {
		switch a {
		case "--yes":
			confirmed = true
		case skipReadinessFlag:
			skipCheck = true
		}
	}
	if step == "status" {
		state, err := pki.RotationStatus(pkiDir)
		if err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "CA rotation state: %s\n", state)
		return 0
	}
	steps := map[string]func(string, time.Time) (string, error){
		"start": pki.StartRotation, "abort": pki.AbortRotation, "promote": pki.PromoteRotation,
		"rollback": pki.RollbackRotation, "retire": pki.RetireRotation,
	}
	fn, ok := steps[step]
	if !ok {
		fmt.Fprintf(out, "unknown step %q\n", step)
		return 2
	}
	if !confirmed {
		fmt.Fprintf(out, "refusing to %s the CA rotation without --yes: this changes how the whole fleet is trusted. Read docs/guides/deployment-ca.md first.\n", step)
		return 2
	}
	if step == "promote" || step == "retire" {
		if skipCheck {
			fmt.Fprintf(out, "WARNING: skipping the fleet readiness check for %s. Any agent not ready may lose access.\n", step)
		} else if msg := notReadyReason(step, pkiDir, check); msg != "" {
			fmt.Fprintf(out, "refusing to %s: %s\nFix that, or pass %s if you accept the consequences.\n", step, msg, skipReadinessFlag)
			return 1
		}
	}
	backup, err := fn(pkiDir, time.Now())
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "ca-rotation %s done. Backup of the previous state: %s\nRestart the server for it to take effect.\n", step, backup)
	return 0
}

// notReadyReason returns why promote or retire must not run now, or "" when the fleet is ready.
func notReadyReason(step, pkiDir string, check rotationCheck) string {
	if check == nil {
		return "the fleet readiness cannot be checked (no database connection)."
	}
	state, err := pki.RotationStatus(pkiDir)
	if err != nil {
		return err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rd, applies, err := check(ctx, state)
	if err != nil {
		return "the fleet readiness could not be read: " + err.Error()
	}
	if !applies || rd.Step != step {
		return fmt.Sprintf("the rotation is %s, so there is nothing to %s.", state, step)
	}
	if rd.Ready {
		return ""
	}
	what := "trust the new root"
	if step == "retire" {
		what = "hold a certificate from the new CA"
	}
	if rd.Total == 0 {
		return "no agents are enrolled, so there is nothing to confirm."
	}
	return fmt.Sprintf("%d of %d agents %s. Still pending: %s.", rd.Done, rd.Total, what, strings.Join(rd.Pending, ", "))
}

// databaseRotationCheck reads the fleet's readiness from the database named by DATABASE_URL (the same variable
// the server uses). Without it the check reports that it cannot run, which makes promote and retire refuse.
func databaseRotationCheck(pkiDir string) rotationCheck {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil
	}
	return func(ctx context.Context, state pki.RotationState) (api.RotationReadiness, bool, error) {
		pool, err := db.Connect(ctx, dsn)
		if err != nil {
			return api.RotationReadiness{}, false, err
		}
		defer pool.Close()
		return api.CARotationReadiness(ctx, pool, pkiDir, state)
	}
}
