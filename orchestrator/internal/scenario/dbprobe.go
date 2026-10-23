package scenario

import (
	"fmt"
	"regexp"
	"strings"
)

// dbFixtureNamePat bounds a catalog fixture name (lower-case words joined by
// hyphens). The agent owns the catalog and refuses names it does not have.
var dbFixtureNamePat = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// ExecutorDBProbe is the step executor for named database probes. The agent
// runs these in-process (agent/exec_dbprobe.go); there is no shell involved.
const ExecutorDBProbe = "dbprobe"

// ProductLineDBSim is the product line every dbprobe step must belong to. It
// equals license.ProductDBSim; kept as a literal here only because the
// validator needs no other license symbol.
const ProductLineDBSim = "dbsim"

// Caps on requested per-step limits. They mirror the agent's own caps
// (agent/dbprobe MaxRowsCap/MaxTimeoutSecCap/MaxConnsCap); the agent re-checks
// them, these only reject a bad scenario early.
const (
	DBMaxRowsCap    = 1_000_000
	DBMaxTimeoutCap = 3600
	DBMaxConnsCap   = 64
)

func isDBProbeExecutor(e string) bool { return strings.EqualFold(e, ExecutorDBProbe) }

// ValidateDBProbeSteps checks the structural rules for dbprobe steps. It does
// not know the probe registry or the target registry; the dbsim builder checks
// those. Rules: executor dbprobe requires the dbsim product line, db_target and
// db_probe, and forbids command text, payloads, cleanup and a host-event
// marker; the db_* fields are forbidden on any other executor; requested
// limits must be positive and within the caps.
func (s *Scenario) ValidateDBProbeSteps() error {
	for i, st := range s.Steps {
		n := i + 1
		hasDB := st.DBTarget != "" || st.DBProbe != "" || len(st.DBParams) > 0 || st.DBLimits != nil || st.DBFixture != ""
		if !isDBProbeExecutor(st.Executor) {
			if hasDB {
				return fmt.Errorf("step %d (%q): db_* fields are only valid with executor %q", n, st.Name, ExecutorDBProbe)
			}
			continue
		}
		switch {
		case s.ProductLine != ProductLineDBSim:
			return fmt.Errorf("step %d (%q): dbprobe steps require product_line %q", n, st.Name, ProductLineDBSim)
		case strings.TrimSpace(st.DBTarget) == "":
			return fmt.Errorf("step %d (%q): dbprobe step requires db_target", n, st.Name)
		case strings.TrimSpace(st.DBProbe) == "":
			return fmt.Errorf("step %d (%q): dbprobe step requires db_probe", n, st.Name)
		case st.Command != "":
			return fmt.Errorf("step %d (%q): dbprobe step must not carry command text", n, st.Name)
		case len(st.Payloads) > 0:
			return fmt.Errorf("step %d (%q): dbprobe step must not carry payloads", n, st.Name)
		case st.Cleanup != "":
			return fmt.Errorf("step %d (%q): dbprobe step must not carry a cleanup script", n, st.Name)
		case st.Marker != "":
			return fmt.Errorf("step %d (%q): dbprobe step must not set a host-event marker (the builder issues the probe marker)", n, st.Name)
		}
		if st.DBFixture != "" && !dbFixtureNamePat.MatchString(st.DBFixture) {
			return fmt.Errorf("step %d (%q): db_fixture %q is not a valid fixture name", n, st.Name, st.DBFixture)
		}
		if l := st.DBLimits; l != nil {
			if l.MaxRows <= 0 || l.TimeoutSec <= 0 || l.MaxConns <= 0 {
				return fmt.Errorf("step %d (%q): db_limits values must all be > 0", n, st.Name)
			}
			if l.MaxRows > DBMaxRowsCap || l.TimeoutSec > DBMaxTimeoutCap || l.MaxConns > DBMaxConnsCap {
				return fmt.Errorf("step %d (%q): db_limits exceed the maximums", n, st.Name)
			}
		}
	}
	return nil
}

// hasDBProbeSteps reports whether any step uses the dbprobe executor.
func (s *Scenario) hasDBProbeSteps() bool {
	for _, st := range s.Steps {
		if isDBProbeExecutor(st.Executor) {
			return true
		}
	}
	return false
}

// stepsUseDBFields reports whether any step sets a db_* field, whatever its executor.
func stepsUseDBFields(steps []Step) bool {
	for _, st := range steps {
		if st.DBTarget != "" || st.DBProbe != "" || len(st.DBParams) > 0 || st.DBLimits != nil || st.DBFixture != "" {
			return true
		}
	}
	return false
}
