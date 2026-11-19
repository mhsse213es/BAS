// Package rwrecover grades the Recovery capability for a VSS deletion attempt
// from the copy counts observed before the attempt and after it. Grading is
// pure: callers supply the step outputs and get a verdict back.
package rwrecover

import (
	"regexp"
	"strconv"

	"github.com/audspect/bas/internal/rwevidence"
)

var (
	enumeratedRe = regexp.MustCompile(`EXEC T1490: (\d+) VSS shadow copy\(ies\) enumerated`)
	noCopiesRe   = regexp.MustCompile(`No VSS shadow copies found`)
	survivalRe   = regexp.MustCompile(`EXEC T1490: survival check -- (\d+) VSS shadow copy\(ies\) present`)
)

// parseEnumeratedCount reads the pre-attempt copy count from the enumeration
// step. An enumeration that reports no copies prints no count, so that case is
// read as zero.
func parseEnumeratedCount(details string) (int, bool) {
	if m := enumeratedRe.FindStringSubmatch(details); m != nil {
		n, err := strconv.Atoi(m[1])
		return n, err == nil
	}
	if noCopiesRe.MatchString(details) {
		return 0, true
	}
	return 0, false
}

// parseSurvivalCount reads the post-attempt copy count from the survival step.
func parseSurvivalCount(details string) (int, bool) {
	m := survivalRe.FindStringSubmatch(details)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

// Grade returns the survival result for a deletion attempt.
//
// deletionPerformed is true only when the deletion step itself reported that it
// removed a copy. Without a deletion there is nothing targeted, so the result
// is indeterminate. When the copy count fell, the targeted copies were lost.
// When it did not fall, they survived. An unreadable count on either side, or
// zero copies before the attempt, is indeterminate.
func Grade(deletionPerformed bool, enumerateDetails, survivalDetails string) rwevidence.SurvivalResult {
	if !deletionPerformed {
		return rwevidence.SurvivalIndeterminate
	}
	pre, ok := parseEnumeratedCount(enumerateDetails)
	if !ok || pre == 0 {
		return rwevidence.SurvivalIndeterminate
	}
	post, ok := parseSurvivalCount(survivalDetails)
	if !ok {
		return rwevidence.SurvivalIndeterminate
	}
	if post < pre {
		return rwevidence.SurvivalLost
	}
	return rwevidence.SurvivalConfirmed
}
