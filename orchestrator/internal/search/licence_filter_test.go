package search

import "testing"

// A run is shown only when its scenario is loaded and licensed now. A run whose scenario is not
// permitted, or no longer loaded, is left out of search.
func TestKeepRunRow_OnlyLicensedLoadedScenarios(t *testing.T) {
	allowed := func(id string) bool { return id == "av-ngav-assessment" }
	if !keepRunRow(allowed, "av-ngav-assessment") {
		t.Fatal("licensed scenario run was dropped")
	}
	if keepRunRow(allowed, "apt29-kill-chain") {
		t.Fatal("unlicensed scenario run was kept")
	}
	if keepRunRow(allowed, "deleted-custom-sc") {
		t.Fatal("run of a scenario no longer loaded was kept")
	}
}
