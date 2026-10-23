package k8sscenario

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// Synthetic secret read-access verification (scenario 1). The lab fixtures are created once by the cluster admin; the
// engine only rotates the value, adds the probe to one binding, reads with the probe's token, and removes it again.
// Every target is fixed, so a run cannot choose its own object. See
// docs/superpowers/specs/2026-10-23-k8s-synthetic-secret-read-design.md.

// SynthLabel marks the one secret this action may touch. The snapshot refuses any secret without it.
const SynthLabel = "bas.audspect.io/synthetic"

const (
	synthSecret  = "bas-synthetic-secret"
	synthBinding = "bas-synthetic-secret-probe"
	synthRole    = "bas-synthetic-secret-reader"
)

// Read observations. They are findings about the probe's access, recorded apart from the run's state.
const (
	ObservationSucceeded    = "READ_SUCCEEDED"
	ObservationDenied       = "READ_DENIED"
	ObservationInconclusive = "READ_INCONCLUSIVE"
)

// synthSnap holds the run's secret material. The value and the token are cleared before the run returns.
type synthSnap struct {
	newValue    string
	token       []byte
	expires     time.Time
	minted      bool
	observation string
}

// wipe overwrites the token bytes and drops the value. The observation and the minted flag are kept for the summary.
func (s *synthSnap) wipe() {
	for i := range s.token {
		s.token[i] = 0
	}
	s.token = nil
	s.newValue = ""
}

// randomValue returns a fresh unguessable value. It is never logged.
func randomValue() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// probeSubject is the RoleBinding subject for the probe ServiceAccount in namespace ns.
func probeSubject(ns string) string {
	return "ServiceAccount/" + ns + "/" + probeServiceAccount
}

// syntheticSecretAction grants the probe read access to the synthetic secret, reads it with the probe's token, then
// removes the grant. The token cannot be revoked, so a successful run ends DISCARDED_NOT_REVOKED.
func syntheticSecretAction() *Action {
	return &Action{
		ID:          "synthetic-secret-read",
		unrevocable: true,
		validate: func(params map[string]string) error {
			if len(params) != 0 {
				return errors.New("this action takes no parameters")
			}
			return nil
		},
		plan: func(ns string, _ map[string]string) []string {
			return []string{
				"check that Secret " + ns + "/" + synthSecret + " carries " + SynthLabel + "=true",
				"check that RoleBinding " + ns + "/" + synthBinding + " has no subjects and references " + synthRole,
				"rotate the secret's value to a fresh random value (kept in memory only)",
				"add ServiceAccount " + ns + "/" + probeServiceAccount + " to the binding",
				"mint a " + fmt.Sprint(probeTokenSeconds) + "-second token for the probe and read the secret with it",
				"remove the probe from the binding, then verify it is removed and the probe can no longer read the secret",
			}
		},
		snapshot: func(ctx context.Context, c Client, req RunRequest) (any, error) {
			ns := req.Namespace
			labels, exists, err := c.SyntheticSecretLabels(ctx, ns, synthSecret)
			if err != nil {
				return nil, err
			}
			if !exists {
				return nil, errors.New("synthetic secret not found")
			}
			if labels[SynthLabel] != "true" {
				return nil, errors.New("secret is not the synthetic fixture")
			}
			b, ok, err := c.GetBinding(ctx, ns, synthBinding)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errors.New("synthetic binding not found")
			}
			if b.RoleName != synthRole {
				return nil, errors.New("synthetic binding references an unexpected role")
			}
			if len(b.Subjects) != 0 {
				return nil, errors.New("synthetic binding already has subjects; refusing to run")
			}
			return &synthSnap{}, nil
		},
		apply: func(ctx context.Context, c Client, req RunRequest, snap any) error {
			s := snap.(*synthSnap)
			v, err := randomValue()
			if err != nil {
				return err
			}
			s.newValue = v
			if err := c.SetSecretValue(ctx, req.Namespace, synthSecret, v); err != nil {
				return err
			}
			return c.SetBindingSubjects(ctx, req.Namespace, synthBinding, []string{probeSubject(req.Namespace)})
		},
		verify: func(ctx context.Context, c Client, req RunRequest, snap any) error {
			s := snap.(*synthSnap)
			ns := req.Namespace
			iss, err := c.IssueToken(ctx, ns, probeServiceAccount, probeTokenSeconds)
			if err != nil {
				s.observation = ObservationInconclusive
				return errors.New("token mint failed")
			}
			s.token = iss.Token
			s.expires = iss.Expires
			s.minted = true
			value, allowed, err := c.ReadSecretAs(ctx, s.token, ns, synthSecret)
			switch {
			case err != nil:
				s.observation = ObservationInconclusive
				return errors.New("read failed")
			case !allowed:
				s.observation = ObservationDenied
				return nil
			case value == s.newValue:
				s.observation = ObservationSucceeded
				return nil
			default:
				s.observation = ObservationInconclusive
				return errors.New("read returned a value other than the rotated one")
			}
		},
		rollback: func(ctx context.Context, c Client, req RunRequest, _ any) error {
			return c.SetBindingSubjects(ctx, req.Namespace, synthBinding, nil)
		},
		verifyRolledBack: func(ctx context.Context, c Client, req RunRequest, snap any) error {
			s := snap.(*synthSnap)
			defer s.wipe()
			ns := req.Namespace
			b, ok, err := c.GetBinding(ctx, ns, synthBinding)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("synthetic binding is missing")
			}
			if len(b.Subjects) != 0 {
				return errors.New("probe is still bound after rollback")
			}
			if len(s.token) == 0 {
				return nil
			}
			_, allowed, err := c.ReadSecretAs(ctx, s.token, ns, synthSecret)
			if err != nil {
				return errors.New("post-rollback read could not be checked")
			}
			if allowed {
				return errors.New("probe can still read the secret after the grant was removed")
			}
			return nil
		},
		observation: func(snap any) string {
			return snap.(*synthSnap).observation
		},
		summary: func(snap any) string {
			s := snap.(*synthSnap)
			msg := "observation " + s.observation + "; grant removed and verified"
			if s.minted {
				msg += "; token discarded, valid until " + s.expires.UTC().Format(time.RFC3339) + " and cannot be revoked"
			} else {
				msg += "; no token was minted"
			}
			return msg
		},
	}
}
