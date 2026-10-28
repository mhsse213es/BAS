// agent/identity_reset.go
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"audspect/agent/preflight"
)

// identityFiles are the enrollment files the agent keeps in its certificate directory.
var identityFiles = []string{"agent-cert.pem", "agent-key.pem", "enrollment-state"}

// clearStaleIdentity moves the agent's enrollment identity aside when its certificate was not
// issued by the deployment CA being installed. The server never accepts a certificate from another
// CA, so keeping one only blocks enrollment. The files are moved, not deleted. It reports whether
// anything was moved. With no identity present, or one that still chains to caPEM, it does nothing.
func clearStaleIdentity(caPEM []byte) (bool, error) {
	dir, _, certPath, _ := certPaths()
	if _, err := os.Stat(certPath); err != nil {
		return false, nil
	}
	if certChainsTo(certPath, caPEM) {
		return false, nil
	}
	backup := dir + ".replaced-" + time.Now().UTC().Format("20060102T150405Z")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		return false, fmt.Errorf("create %s: %w", backup, err)
	}
	for _, name := range identityFiles {
		src := filepath.Join(dir, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.Rename(src, filepath.Join(backup, name)); err != nil {
			return false, fmt.Errorf("move %s: %w", src, err)
		}
	}
	return true, nil
}

// identityStatus reports, without changing anything, whether the installed agent identity is stale for the CA in caPEM:
// preflight.CodeIdentityStale if a certificate is present and does not chain to it, otherwise 0 (current, or no identity).
func identityStatus(caPEM []byte) int {
	_, _, certPath, _ := certPaths()
	if _, err := os.Stat(certPath); err != nil {
		return 0
	}
	if _, err := os.ReadFile(certPath); err != nil {
		return 0 // cannot read it (for example, not run with enough rights): unknown, so never call it stale
	}
	if certChainsTo(certPath, caPEM) {
		return 0
	}
	return preflight.CodeIdentityStale
}

// runIdentityStatusCLI implements --identity-status: verify the deployment configuration, then report identityStatus.
func runIdentityStatusCLI(f deployFlags, now time.Time, out io.Writer) int {
	if f.ConfigPath == "" {
		fmt.Fprintln(out, "deployment configuration rejected: --identity-status needs --config")
		return preflight.CodeConfigRejected
	}
	f.Server, f.EnrollPort, f.CARootPath = "", "", ""
	d, err := resolveDeployment(f, now)
	if err != nil {
		fmt.Fprintln(out, err.Error())
		return preflight.CodeConfigRejected
	}
	code := identityStatus(d.CARootPEM)
	if code == preflight.CodeIdentityStale {
		fmt.Fprintln(out, "the installed agent identity was not issued by this deployment's CA")
	}
	return code
}

// resetIdentity re-enrols an installed agent whose identity belongs to a different CA, without touching the service or
// any installed file: it moves the stale identity aside, stores the new deployment CA, and spends the enrolment token
// (if any) through enroll. It reports whether it reset anything; a current or absent identity changes nothing and spends
// no token. An enrolment failure is returned so the installer can report it.
func resetIdentity(dep deployment, token string, enroll func(token string) error) (bool, error) {
	moved, err := clearStaleIdentity(dep.CARootPEM)
	if err != nil {
		return false, fmt.Errorf("reset old agent identity: %w", err)
	}
	if !moved {
		return false, nil
	}
	if err := saveDeploymentCARoot(dep.CARootPEM); err != nil {
		return true, fmt.Errorf("deployment CA root: %w", err)
	}
	if token != "" {
		if err := enroll(token); err != nil {
			return true, err
		}
	}
	return true, nil
}

// certChainsTo reports whether the PEM certificate at certPath verifies against the CA in caPEM.
func certChainsTo(certPath string, caPEM []byte) bool {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return false
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

// runResetIdentityCLI implements --reset-identity for installers that find an agent already installed.
func runResetIdentityCLI(f deployFlags, secretArg string, secretStdin bool, tokenFile string, tokenStdin bool, _ string) int {
	if f.ConfigPath == "" {
		fmt.Fprintln(os.Stderr, "deployment configuration rejected: --reset-identity needs --config")
		return preflight.CodeConfigRejected
	}
	f.Server, f.EnrollPort, f.CARootPath = "", "", ""
	dep, err := resolveDeployment(f, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return preflight.CodeConfigRejected
	}
	secret, secretFromStdin, err := secretFromFlags(secretArg, secretStdin, os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if secret == "" && !secretFromStdin {
		secret = os.Getenv("BAS_AGENT_SECRET")
	}
	tok, err := resolveEnrollmentToken(tokenFile, tokenStdin, secretFromStdin, os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	enroll := func(token string) error {
		cfg := Config{ServerURL: dep.Server, AgentSecret: secret, EnrollmentToken: token}
		return enrollAtInstall(context.Background(), cfg, dep.EnrollPort, collectIdentity().AgentID)
	}
	reset, err := resetIdentity(dep, tok, enroll)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return installExitCode(err)
	}
	if reset {
		fmt.Println("[*] old agent identity was issued by a different CA; moved aside and re-enrolled")
	} else {
		fmt.Println("[=] agent identity matches this deployment; nothing changed")
	}
	return 0
}
