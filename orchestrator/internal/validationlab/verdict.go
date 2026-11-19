package validationlab

// VerdictForRun gives the lab's outcome for a completed run from its stored results: PASS, FAIL, NO_DATA or ERROR,
// with the reason. The CI gate reads verdicts through this so CI and the lab use one set of rules.
func VerdictForRun(resultsJSON []byte) (outcome, reason string) {
	return classifyCompletedRun(resultsJSON)
}
