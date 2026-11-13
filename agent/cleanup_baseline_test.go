package main

import "testing"

// A pre-step baseline that could not be read (its query failed, so the category is absent) must not make every
// item that already existed look like a leftover. That is what made ordinary Windows tasks show as leaked.
func TestReconcileCleanupVerdict_MissingBaselineIsNotALeak(t *testing.T) {
	pre := &SystemSnapshot{Lists: map[string][]string{}, Files: map[string][]byte{}, Unavailable: map[string]bool{"schtasks": true}}
	post := &SystemSnapshot{
		Lists: map[string][]string{"schtasks": {`\Microsoft\Windows\Edge\Update`, `\OneDrive\Startup`}},
		Files: map[string][]byte{},
	}
	residual, verdict := reconcileCleanupVerdict(pre, post, "reverted")
	for _, r := range residual {
		if len(r) >= len("schtask:") && r[:len("schtask:")] == "schtask:" {
			t.Errorf("existing task reported as a leftover with no baseline: %q", r)
		}
	}
	if verdict == "partial" || verdict == "leaked" {
		t.Errorf("verdict = %q: an unreadable baseline must not be scored as a leak", verdict)
	}
}

// A category that was read before the step, and has a new item after it, is still a real leftover.
func TestReconcileCleanupVerdict_RealNewTaskStillLeaks(t *testing.T) {
	pre := &SystemSnapshot{Lists: map[string][]string{"schtasks": {`\Existing`}}, Files: map[string][]byte{}}
	post := &SystemSnapshot{Lists: map[string][]string{"schtasks": {`\Existing`, `\BAS-V-new`}}, Files: map[string][]byte{}}
	residual, verdict := reconcileCleanupVerdict(pre, post, "reverted")
	if len(residual) != 1 || residual[0] != `schtask:\BAS-V-new` {
		t.Errorf("residual = %v, want only the new task", residual)
	}
	if verdict != "partial" {
		t.Errorf("verdict = %q, want partial", verdict)
	}
}
