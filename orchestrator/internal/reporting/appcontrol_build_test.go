package reporting

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

// A path's observed state records the Windows build it ran on, so the report
// shows which build a result belongs to.
func TestBuildAppControlSection_ObservedRecordsBuild(t *testing.T) {
	out := "APPCTL_FAMILY: indirect_execution\nAPPCTL_HOST: os_build=19045\nAPPCTL_COVERAGE: Exe=Enabled\nAPPCTL_DETECTION: source=sysmon_process_create result=visible\nAPPCTL_OUTCOME: blocked_as_expected\n"
	sec := buildAppControlSection("run-b", []models.SimulationResult{
		appCtlResult("Application control indirect execution via cmd.exe parent (T1202)", "T1202", out),
	})
	if got := sec.Rows[0].Observed; got != "Exe=Enabled; build 19045" {
		t.Errorf("Observed = %q, want \"Exe=Enabled; build 19045\"", got)
	}
}
