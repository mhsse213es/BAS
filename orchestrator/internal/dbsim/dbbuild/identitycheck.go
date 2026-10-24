package dbbuild

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/scenario"
)

// identityCheckTechnique is the ATT&CK technique the identity-check step is
// filed under (the account-discovery family the other read-only probes use);
// it only selects the execution-class catalog entry.
const identityCheckTechnique = "T1078"

// BuildIdentityCheckStep compiles the one signed read-only step that runs
// check_readonly_identity for a target, with the same rules as BuildSteps: the
// connection fields, mode and trust flags come only from t, the run id comes
// from opt.RunID (or is generated), the marker is generated here, and the step
// has exactly the shape the agent accepts.
//
// The gate is dbsim.AuthorizeIdentityCheck, not Authorize: this step is what
// earns ReadOnlyIdentityVerified, so it cannot require it, and it does not need
// the client mode setting (it only reads catalogs and the caller is Admin-only).
func BuildIdentityCheckStep(ctx context.Context, t dbsim.Target, opt Options) (scenario.ScenarioStep, dbsim.DBProbeSpec, error) {
	if err := ctx.Err(); err != nil {
		return scenario.ScenarioStep{}, dbsim.DBProbeSpec{}, err
	}
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	if err := dbsim.AuthorizeIdentityCheck(t, now(), opt.RunExpiry); err != nil {
		return scenario.ScenarioStep{}, dbsim.DBProbeSpec{}, fmt.Errorf("dbbuild: %w", err)
	}
	entry, ok := dbsim.LookupProbeEntry(dbsim.ProbeCheckReadOnlyIdentity)
	if !ok {
		return scenario.ScenarioStep{}, dbsim.DBProbeSpec{}, fmt.Errorf("dbbuild: probe %q is not registered", dbsim.ProbeCheckReadOnlyIdentity)
	}
	if !strings.HasPrefix(t.CredentialRef, CredentialRefPrefix) || len(t.CredentialRef) == len(CredentialRefPrefix) {
		return scenario.ScenarioStep{}, dbsim.DBProbeSpec{}, fmt.Errorf("dbbuild: target %q has no %q credential reference", t.ID, CredentialRefPrefix)
	}
	if strings.TrimSpace(t.Host) == "" {
		return scenario.ScenarioStep{}, dbsim.DBProbeSpec{}, fmt.Errorf("dbbuild: target %q has no host", t.ID)
	}
	runID := opt.RunID
	if runID == "" {
		h, err := randHex(8)
		if err != nil {
			return scenario.ScenarioStep{}, dbsim.DBProbeSpec{}, err
		}
		runID = RunIDPrefix + h
	}
	mh, err := randHex(12)
	if err != nil {
		return scenario.ScenarioStep{}, dbsim.DBProbeSpec{}, err
	}
	limits := DefaultLimits
	spec := dbsim.DBProbeSpec{
		Engine: t.Engine, ProbeID: entry.ID, TargetID: t.ID,
		Host: t.Host, Port: t.Port, Database: t.Database, TLSMode: t.TLSMode,
		ExpectedIdentity: t.ExpectedIdentity, CredentialRef: t.CredentialRef,
		RunID: runID, Marker: MarkerPrefix + mh,
		Mode: t.Mode, Limits: limits,
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return scenario.ScenarioStep{}, dbsim.DBProbeSpec{}, fmt.Errorf("dbbuild: marshal spec: %w", err)
	}
	const name = "Read-only identity check"
	steps := []scenario.ScenarioStep{{
		TaskID: scenario.TaskID(identityCheckTechnique, name), TechniqueID: identityCheckTechnique, Name: name,
		Framework: "custom", Executor: scenario.ExecutorDBProbe,
		Command:    entry.ID,
		TimeoutSec: limits.TimeoutSec + 10,
		ActionKey:  ProbeActionKey(entry.Class),
		DBProbe:    raw,
	}}
	scenario.AttachExecutionClassifications(steps)
	if want := ExpectedExecutionClass(entry.Class); steps[0].ExecutionClass != want {
		return scenario.ScenarioStep{}, dbsim.DBProbeSpec{}, fmt.Errorf("dbbuild: identity check resolved execution class %q, want %q",
			steps[0].ExecutionClass, want)
	}
	return steps[0], spec, nil
}
