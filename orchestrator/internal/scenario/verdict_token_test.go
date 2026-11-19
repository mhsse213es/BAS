package scenario

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// verdictTokenPattern matches an output line that begins with a verdict word but does not
// use the exact "WORD:" form the interpreter reads (interpreter.go dominantVerdict). Such a
// line is invisible to the verdict logic: with exit 0 the step is scored PASS, so a
// "FAIL [CSCRF-2.1]: ..." line silently becomes a pass. Found 2026-11-12 in cscrf-mii-drill,
// dcsync-replication-rights-live-verification, exposure-validation and akira-kill-chain.
var verdictTokenPattern = regexp.MustCompile(`(?i)(Write-Output|Write-Host|echo)\s+"(PASS|FAIL|SKIP|ERROR)[^:\w]`)

// TestVerdictTokens_ExactForm fails if any scenario prints a verdict word without the
// colon directly after it. Fix the line to "FAIL: [ID] ..." rather than adding an exception.
func TestVerdictTokens_ExactForm(t *testing.T) {
	entries, err := os.ReadDir(contractScenarioDir)
	if err != nil {
		t.Fatalf("read scenarios: %v", err)
	}
	var offenders []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(contractScenarioDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if verdictTokenPattern.MatchString(line) {
				offenders = append(offenders, e.Name()+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("%d verdict line(s) not in the exact WORD: form the interpreter reads:\n%s",
			len(offenders), strings.Join(offenders, "\n"))
	}
}
