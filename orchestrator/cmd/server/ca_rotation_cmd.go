package main

import (
	"fmt"
	"io"
	"time"

	"github.com/audspect/bas/internal/pki"
)

// runCARotation drives a planned CA rotation from the command line (audit F-09), offline, against the PKI
// directory: `ca-rotation status|start|abort|promote|rollback|retire [--yes]`. Every step except status
// changes how the whole fleet is trusted, so it must be confirmed with --yes. Steps take effect when the
// server next starts. Returns the process exit code.
func runCARotation(args []string, pkiDir string, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(out, "usage: ca-rotation status|start|abort|promote|rollback|retire [--yes]")
		return 2
	}
	step := args[0]
	confirmed := false
	for _, a := range args[1:] {
		if a == "--yes" {
			confirmed = true
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
	backup, err := fn(pkiDir, time.Now())
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "ca-rotation %s done. Backup of the previous state: %s\nRestart the server for it to take effect.\n", step, backup)
	return 0
}
