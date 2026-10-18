package dlpfixture

// FixtureIDForStep returns the catalog Fixture.ID whose Occurrences contain
// exactly this stepName, and true if the match is unambiguous. Zero matches,
// or a stepName claimed by more than one different fixture, return ("",
// false) -- callers must treat that as "no stable fixture reference
// available", never guess one. This is an exact match against a real step's
// own name, never an inference from a scenario's ID or description.
func FixtureIDForStep(stepName string) (string, bool) {
	fixtures, err := AllFixtures()
	if err != nil {
		return "", false
	}
	return fixtureIDForStepIn(fixtures, stepName)
}

func fixtureIDForStepIn(fixtures []Fixture, stepName string) (string, bool) {
	if stepName == "" {
		return "", false
	}
	var matchID string
	matched := false
	for _, f := range fixtures {
		for _, occ := range f.Occurrences {
			if occ.StepName != stepName {
				continue
			}
			if matched && matchID != f.ID {
				return "", false // ambiguous across different fixtures
			}
			matchID = f.ID
			matched = true
		}
	}
	return matchID, matched
}
