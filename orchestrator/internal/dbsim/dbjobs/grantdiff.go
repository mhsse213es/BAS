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
	if !dbsim.IsPolicyDiffProbe(spec.ProbeID) || s.GrantPolicy == nil || ex.DBProbe == nil || ex.DBProbe.ErrorClass != "" {
		return nil
	}
	pol, ok := s.GrantPolicy(job, rec)
	if !ok {
		return nil
	}
	var d dbsim.DiffReport
	switch spec.ProbeID {
	case dbsim.ProbeReadGrants:
		d = dbsim.Report(pol, dbsim.GrantsFromProbe(*ex.DBProbe))
	case dbsim.ProbeReadGlobalPrivileges:
		d = dbsim.ReportGlobal(pol, dbsim.GlobalFromProbe(*ex.DBProbe))
	case dbsim.ProbeReadMemberships:
		d = dbsim.ReportMemberships(pol, dbsim.MembershipsFromProbe(*ex.DBProbe))
	default:
		return nil
	}
	return &d
}
