package scenario

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// A scenario file must not be able to grant itself the lab spray exemption.
func TestLivePolicy_LabExceptionNotReadFromYAML(t *testing.T) {
	var lp LivePolicy
	src := "labException: true\nblock_on_domain_controller: true\n"
	if err := yaml.Unmarshal([]byte(src), &lp); err != nil {
		t.Fatal(err)
	}
	if lp.LabException {
		t.Fatal("LabException must not be settable from a scenario file (yaml:\"-\")")
	}
	if !lp.BlockOnDomainController {
		t.Fatal("sanity: other fields still parse")
	}
}
