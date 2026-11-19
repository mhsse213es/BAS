package api

import (
	"log"
	"os"

	"github.com/audspect/bas/internal/dbsim"
)

// Environment variables that bind one DB-02 policy file to one target. A policy
// has no target of its own, so it applies only to the target named here; with
// either variable unset, no policy is applied and grant steps never pass.
const (
	envDBSimPolicyFile   = "BAS_DBSIM_POLICY_FILE"
	envDBSimPolicyTarget = "BAS_DBSIM_POLICY_TARGET"
)

// dbsimGrantSource holds the policy loaded at start for its one target.
type dbsimGrantSource struct {
	target string
	policy dbsim.Policy
}

// loadDBSimGrantSource reads the bound policy file. Any problem is logged and
// yields nil: the grants dimension then grades without a policy (fail closed).
func loadDBSimGrantSource() *dbsimGrantSource {
	file, target := os.Getenv(envDBSimPolicyFile), os.Getenv(envDBSimPolicyTarget)
	if file == "" || target == "" {
		return nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		log.Printf("[dbsim] policy file not readable; grant steps will not pass: %v", err)
		return nil
	}
	p, err := dbsim.PolicyFromJSON(data)
	if err != nil {
		log.Printf("[dbsim] policy file invalid; grant steps will not pass: %v", err)
		return nil
	}
	return &dbsimGrantSource{target: target, policy: p}
}

// dbsimGrantPolicy is the dbjobs GrantPolicy hook: the policy for this target only.
func (s *dbsimGrantSource) dbsimGrantPolicy(_ dbsim.RunJob, rec dbsim.TargetRecord) (dbsim.Policy, bool) {
	if s == nil || rec.ID != s.target {
		return dbsim.Policy{}, false
	}
	return s.policy, true
}
