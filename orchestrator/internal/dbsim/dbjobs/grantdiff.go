package dbjobs

import (
	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbrun"
)

// grantDiffFor runs the DB-02 policy comparison for a read_grants step. It returns nil,
// so the step grades as it did before (never PASS on grants), unless all of these hold:
// the probe is read_grants, a policy is configured for the target, and the probe ran
// without an error. A clean policy diff is what lets the grants dimension pass.
func (s *Service) grantDiffFor(job dbsim.RunJob, rec dbsim.TargetRecord, ex dbrun.AgentExec, spec dbsim.DBProbeSpec) *dbsim.DiffReport {
	if spec.ProbeID != dbsim.ProbeReadGrants || s.GrantPolicy == nil || ex.DBProbe == nil || ex.DBProbe.ErrorClass != "" {
		return nil
	}
	pol, ok := s.GrantPolicy(job, rec)
	if !ok {
		return nil
	}
	d := dbsim.Report(pol, dbsim.GrantsFromProbe(*ex.DBProbe))
	return &d
}
