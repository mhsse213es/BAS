package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"audspect/agent/deployconfig"
)

// deployFlags are the inputs that describe where the agent should connect.
// Either the individual flags (legacy/manual) or a signed deployment config
// plus its independently obtained fingerprint -- never a mix.
type deployFlags struct {
	ConfigPath  string // --config
	Fingerprint string // --config-fingerprint
	Server      string // --server
	EnrollPort  string // --enroll-port
	CARootPath  string // --ca-root
}

// deployment is the resolved connection target.
type deployment struct {
	Server     string
	EnrollPort string
	CARootPEM  []byte
}

// caFileError marks a failure to read the --ca-root file, which keeps its own
// exit code (invalid CA) apart from a config trust failure.
type caFileError struct{ msg string }

func (e *caFileError) Error() string { return e.msg }

// resolveDeployment returns the connection target. With --config the signed
// file is verified against the mandatory fingerprint (fail closed: no
// fingerprint, mismatch, bad signature or invalid content returns an error and
// an empty result) and the individual flags must not also be given, so a
// verified value can never be silently overridden or mixed with an unverified
// one.
func resolveDeployment(f deployFlags, now time.Time) (deployment, error) {
	if f.ConfigPath == "" {
		if f.Fingerprint != "" {
			return deployment{}, errors.New("--config-fingerprint is only valid together with --config")
		}
		var ca []byte
		if f.CARootPath != "" {
			b, err := os.ReadFile(f.CARootPath)
			if err != nil {
				return deployment{}, &caFileError{"cannot read the deployment CA file given with --ca-root"}
			}
			ca = b
		}
		return deployment{Server: f.Server, EnrollPort: f.EnrollPort, CARootPEM: ca}, nil
	}
	if f.Server != "" || f.EnrollPort != "" || f.CARootPath != "" {
		return deployment{}, errors.New("--config cannot be combined with --server, --enroll-port or --ca-root: the signed configuration supplies them")
	}
	fh, err := os.Open(f.ConfigPath)
	if err != nil {
		return deployment{}, errors.New("cannot read the deployment configuration file given with --config")
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, deployconfig.MaxEnvelopeBytes+1))
	if err != nil {
		return deployment{}, errors.New("cannot read the deployment configuration file given with --config")
	}
	cfg, err := deployconfig.Verify(b, f.Fingerprint, now)
	if err != nil {
		return deployment{}, fmt.Errorf("deployment configuration rejected: %w", err)
	}
	d := deployment{Server: cfg.ServerURL, EnrollPort: cfg.EnrollPort}
	if cfg.CARootPEM != "" {
		d.CARootPEM = []byte(cfg.CARootPEM)
	}
	return d, nil
}
