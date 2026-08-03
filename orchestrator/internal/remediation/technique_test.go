package remediation

import "testing"

func TestTechniqueVerificationRun_ZeroValue(t *testing.T) {
	var r TechniqueVerificationRun
	if r.Status != "" || r.Engine != "" {
		t.Errorf("zero-value TechniqueVerificationRun = %+v, want empty Status/Engine", r)
	}
}
