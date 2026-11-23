package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/api"
	"github.com/audspect/bas/internal/pki"
)

func fixedReadiness(r api.RotationReadiness, err error) rotationCheck {
	return func(context.Context, pki.RotationState) (api.RotationReadiness, bool, error) { return r, true, err }
}

func stateOf(t *testing.T, dir string) pki.RotationState {
	t.Helper()
	s, err := pki.RotationStatus(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func prepared(t *testing.T) string {
	t.Helper()
	dir := rotationDir(t)
	if _, err := pki.StartRotation(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	return dir
}

// promote switches the issuing CA for the whole fleet, so it must not run ahead of the agents: with the check
// saying not ready it refuses and changes nothing, and it names who is still pending.
func TestCARotationPromote_RefusedWhileAgentsAreStillPending(t *testing.T) {
	dir := prepared(t)
	var out bytes.Buffer
	notReady := api.RotationReadiness{Step: "promote", Total: 3, Done: 2, Pending: []string{"agent-c"}}
	if code := runCARotation([]string{"promote", "--yes"}, dir, &out, fixedReadiness(notReady, nil)); code == 0 {
		t.Fatalf("promote must be refused, output: %s", out.String())
	}
	if !strings.Contains(out.String(), "agent-c") || !strings.Contains(out.String(), "2 of 3") {
		t.Errorf("output must say how far the fleet is and who is pending: %q", out.String())
	}
	if got := stateOf(t, dir); got != pki.RotationPrepared {
		t.Fatalf("state = %s, a refused promote must change nothing", got)
	}
}

func TestCARotationPromote_AllowedWhenEveryAgentIsReady(t *testing.T) {
	dir := prepared(t)
	var out bytes.Buffer
	ready := api.RotationReadiness{Step: "promote", Total: 2, Done: 2, Ready: true}
	if code := runCARotation([]string{"promote", "--yes"}, dir, &out, fixedReadiness(ready, nil)); code != 0 {
		t.Fatalf("promote = %d: %s", code, out.String())
	}
	if got := stateOf(t, dir); got != pki.RotationPromoted {
		t.Fatalf("state = %s, want promoted", got)
	}
}

// If readiness cannot be determined (no database, query failed, no check supplied) the safe answer is no.
func TestCARotationPromote_RefusedWhenReadinessCannotBeChecked(t *testing.T) {
	for name, check := range map[string]rotationCheck{
		"no check available": nil,
		"query failed":       fixedReadiness(api.RotationReadiness{}, errors.New("connection refused")),
	} {
		t.Run(name, func(t *testing.T) {
			dir := prepared(t)
			var out bytes.Buffer
			if code := runCARotation([]string{"promote", "--yes"}, dir, &out, check); code == 0 {
				t.Fatalf("promote must be refused, output: %s", out.String())
			}
			if !strings.Contains(out.String(), "--skip-readiness-check") {
				t.Errorf("the refusal must name the explicit override: %q", out.String())
			}
			if got := stateOf(t, dir); got != pki.RotationPrepared {
				t.Fatalf("state = %s, want prepared", got)
			}
		})
	}
}

// The override exists for a fleet the operator knows is fine (or a dead agent they accept losing) but must be asked for.
func TestCARotationPromote_SkipFlagOverridesAndSaysSo(t *testing.T) {
	dir := prepared(t)
	var out bytes.Buffer
	notReady := api.RotationReadiness{Step: "promote", Total: 3, Done: 0, Pending: []string{"a", "b", "c"}}
	if code := runCARotation([]string{"promote", "--yes", "--skip-readiness-check"}, dir, &out, fixedReadiness(notReady, nil)); code != 0 {
		t.Fatalf("promote with the override = %d: %s", code, out.String())
	}
	if !strings.Contains(strings.ToLower(out.String()), "skipp") {
		t.Errorf("the output must say the readiness check was skipped: %q", out.String())
	}
}

func TestCARotationRetire_GatedOnAgentsHoldingNewCACerts(t *testing.T) {
	dir := prepared(t)
	if _, err := pki.PromoteRotation(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	notReady := api.RotationReadiness{Step: "retire", Total: 2, Done: 1, Pending: []string{"agent-b"}}
	if code := runCARotation([]string{"retire", "--yes"}, dir, &out, fixedReadiness(notReady, nil)); code == 0 {
		t.Fatalf("retire must be refused, output: %s", out.String())
	}
	if !strings.Contains(out.String(), "agent-b") {
		t.Errorf("output must name the agent still on an old certificate: %q", out.String())
	}
	if got := stateOf(t, dir); got != pki.RotationPromoted {
		t.Fatalf("state = %s, a refused retire must change nothing", got)
	}
	out.Reset()
	ready := api.RotationReadiness{Step: "retire", Total: 2, Done: 2, Ready: true}
	if code := runCARotation([]string{"retire", "--yes"}, dir, &out, fixedReadiness(ready, nil)); code != 0 {
		t.Fatalf("retire = %d: %s", code, out.String())
	}
}

// start, abort and rollback undo or begin without risking the fleet, so no readiness check is asked of them.
func TestCARotationOtherSteps_DoNotNeedReadiness(t *testing.T) {
	dir := rotationDir(t)
	var out bytes.Buffer
	if code := runCARotation([]string{"start", "--yes"}, dir, &out, nil); code != 0 {
		t.Fatalf("start = %d: %s", code, out.String())
	}
	if code := runCARotation([]string{"abort", "--yes"}, dir, &out, nil); code != 0 {
		t.Fatalf("abort = %d: %s", code, out.String())
	}
}
