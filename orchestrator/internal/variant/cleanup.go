package variant

// WithCleanup sets a template's cleanup and status. A schtasks variant creates a scheduled task, and the agent can kill
// the variant between create and delete. So its cleanup is a check on that task's deterministic name: delete it, then
// fail if it is still there. That cleanup runs in cmd, so a PowerShell base-test cleanup cannot be used for it. The
// status stays unverified until a lab run confirms the check.
func WithCleanup(t Template, cleanup, status string) Template {
	if t.ExecContext == CtxSchedTask {
		t.Cleanup = schedTaskCleanup(t.TechniqueID, t.BaseID, t.Encoding)
		t.CleanupStatus = CleanupUnverified
		return t
	}
	if status == "" {
		status = CleanupUnverified
	}
	t.Cleanup = cleanup
	t.CleanupStatus = status
	return t
}

// schedTaskCleanup deletes the task a schtasks variant creates, then exits 1 if it is still present.
// The delete's own result is ignored, because the task may already be gone; the query decides.
func schedTaskCleanup(techniqueID, baseID, enc string) string {
	name := "BAS-V-" + variantShortHash(techniqueID, baseID, enc)
	return `schtasks.exe /delete /tn "` + name + `" /f >nul 2>&1 & schtasks.exe /query /tn "` + name + `" >nul 2>&1 && (exit /b 1) || exit /b 0`
}
