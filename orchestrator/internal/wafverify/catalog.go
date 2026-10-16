package wafverify

import "fmt"

// AudspectWAFVerifyCatalog returns Audspect's real, current seed
// independent-verification scenario set: one scenario per named item
// from waf.txt Phase 10, the final phase of the waf.txt roadmap.
func AudspectWAFVerifyCatalog() (regression []RegressionScenario, benchmark []BenchmarkScenario, reproduction []ReproductionScenario, remediation []RemediationScenario, coverageGate []CoverageGateScenario, err error) {
	r, err := NewRegressionScenario("WAFVERIFY-001",
		"a scenario's verdict must stay stable, or improve, across repeated runs over time -- a regression is a verdict that got worse without a code or policy change explaining why",
		"manually authored from waf.txt Phase 10's named regression-suites item")
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("loading seed verify catalog: %w", err)
	}

	b, err := NewBenchmarkScenario("WAFVERIFY-002",
		"two vendors' or two versions' verdicts for the same scenario can be ranked against each other to produce a comparative benchmark",
		"manually authored from waf.txt Phase 10's named vendor/version-benchmarks item")
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("loading seed verify catalog: %w", err)
	}

	rep, err := NewReproductionScenario("WAFVERIFY-003",
		"a finding must be reproducible: re-running the same scenario against the same target must produce the same verdict",
		"manually authored from waf.txt Phase 10's named finding-reproduction item")
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("loading seed verify catalog: %w", err)
	}

	rem, err := NewRemediationScenario("WAFVERIFY-004",
		"after a reported fix, re-testing the same scenario must show whether the verdict actually improved, stayed the same, or regressed",
		"manually authored from waf.txt Phase 10's named remediation-retests item")
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("loading seed verify catalog: %w", err)
	}

	cg, err := NewCoverageGateScenario("WAFVERIFY-005",
		"the testing program's own scenario coverage must meet a minimum ratio of exercised to total scenarios before its results can be trusted as representative",
		"manually authored from waf.txt Phase 10's named coverage-quality-gates item", 0.8)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("loading seed verify catalog: %w", err)
	}

	return []RegressionScenario{r}, []BenchmarkScenario{b}, []ReproductionScenario{rep}, []RemediationScenario{rem}, []CoverageGateScenario{cg}, nil
}
