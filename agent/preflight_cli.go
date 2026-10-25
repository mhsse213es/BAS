package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"audspect/agent/preflight"
)

// preflightCLIArgs are the command-line inputs of `--preflight`.
type preflightCLIArgs struct {
	Server            string // --server
	EnrollPort        string // --enroll-port
	CARootPath        string // --ca-root (path to a PEM file; optional)
	SecretArg         string // --secret: refused, present only so misuse gets a clear error
	SecretStdin       bool   // --secret-stdin: the only accepted way to supply the secret
	ConfigPath        string // --config: signed deployment.json (replaces --server/--enroll-port/--ca-root)
	ConfigFingerprint string // --config-fingerprint: independently obtained SHA-256 of the signing certificate
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

	dep, derr := resolveDeployment(deployFlags{
		ConfigPath: a.ConfigPath, Fingerprint: a.ConfigFingerprint,
		Server: a.Server, EnrollPort: a.EnrollPort, CARootPath: a.CARootPath,
	}, time.Now())
	if derr != nil {
		code := preflight.CodeConfigRejected
		var ce *caFileError
		if errors.As(derr, &ce) {
			code = preflight.CodeInvalidCA
		}
		return finish(preflight.Result{Code: code, Message: derr.Error()})
	}
	a.Server, a.EnrollPort = dep.Server, dep.EnrollPort
	caPEM := dep.CARootPEM

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return finish(preflight.Run(ctx, preflight.Params{
		ServerURL: a.Server, EnrollPort: a.EnrollPort, Secret: secret, CARootPEM: caPEM,
	}))
}
