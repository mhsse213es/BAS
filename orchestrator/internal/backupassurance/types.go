// Package backupassurance is a standalone infrastructure-posture engine:
// 6 independent checks against a customer's backup/recovery setup,
// structurally separate from rwevidence (per-attack-attempt outcomes) and
// rwscore (weighted scoring over those outcomes). Pure Go, no DB import --
// controlval.Verdict/SkipReason are reused as value types only, never its
// Provider/CorrelationKey machinery, which assumes an attack-attempt shape
// these checks don't have.
package backupassurance

import "github.com/audspect/bas/internal/controlval"

// Check names one of the 6 backup-assurance checks (ransomware.txt lines
// 51-55 -- the narrative's own order, which is authoritative: the
// decomposition table's "6 sub-checks" row names only 5, dropping
// deletion_protection from its own list while still claiming 6).
type Check string

const (
	CheckDeletionProtection  Check = "deletion_protection"
	CheckImmutability        Check = "immutability"
	CheckOfflineIsolation    Check = "offline_isolation"
	CheckPrivilegeSeparation Check = "privilege_separation"
	CheckRestoreIntegrity    Check = "restore_integrity"
	CheckRPORTO              Check = "rpo_rto"
)

// allChecks is the fixed enum order AssessBackup always returns in.
var allChecks = []Check{
	CheckDeletionProtection, CheckImmutability, CheckOfflineIsolation,
	CheckPrivilegeSeparation, CheckRestoreIntegrity, CheckRPORTO,
}

// simulated is hardcoded for this entire sub-project -- never observer-
// controlled, never a parameter. A future real observer is introduced
// through a separately reviewed change that deliberately revises this
// constant and the database's own CHECK (simulated = TRUE) constraint
// (Task 4) -- not a runtime config flag.
const simulated = true

// CheckResult is one check's classified outcome.
type CheckResult struct {
	Check      Check
	Verdict    controlval.Verdict
	SkipReason controlval.SkipReason
	Reason     string
	Simulated  bool
	Observer   string // always non-empty: a real observerID, or "unconfigured"/"panicked"
}

// Valid delegates to controlval.ValidSkipPair -- the single, shared place
// that catches an invalid Verdict/SkipReason combination, never a second
// copy of the rule.
func (cr CheckResult) Valid() error {
	return controlval.ValidSkipPair(cr.Verdict, cr.SkipReason)
}
