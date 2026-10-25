package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"audspect/agent/preflight"
)

// preflightCLIArgs are the command-line inputs of `--preflight`.
type preflightCLIArgs struct {
	Server      string // --server
	EnrollPort  string // --enroll-port
	CARootPath  string // --ca-root (path to a PEM file; optional)
	SecretArg   string // --secret: refused, present only so misuse gets a clear error
	SecretStdin bool   // --secret-stdin: the only accepted way to supply the secret
}

// runPreflightCLI runs the pre-install checks and returns the process exit
// code (see package preflight for the documented codes). It prints exactly one
// line to out, never the secret, and writes nothing to disk or the service
// manager.
func runPreflightCLI(a preflightCLIArgs, stdin io.Reader, out io.Writer) int {
	finish := func(r preflight.Result) int {
		fmt.Fprintln(out, r.Message)
		return r.Code
	}

	if a.SecretArg != "" {
		return finish(preflight.Result{Code: preflight.CodeInvalidInput,
			Message: "--preflight does not accept --secret: pipe the secret and use --secret-stdin"})
	}
	if !a.SecretStdin {
		return finish(preflight.Result{Code: preflight.CodeInvalidInput,
			Message: "--preflight needs --secret-stdin and the secret on stdin"})
	}
	secret, err := readSecretFromStdin(stdin)
	if err != nil {
		return finish(preflight.Result{Code: preflight.CodeInvalidInput, Message: err.Error()})
	}

	var caPEM []byte
	if a.CARootPath != "" {
		caPEM, err = os.ReadFile(a.CARootPath)
		if err != nil {
			return finish(preflight.Result{Code: preflight.CodeInvalidCA,
				Message: "cannot read the deployment CA file given with --ca-root"})
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return finish(preflight.Run(ctx, preflight.Params{
		ServerURL: a.Server, EnrollPort: a.EnrollPort, Secret: secret, CARootPEM: caPEM,
	}))
}
