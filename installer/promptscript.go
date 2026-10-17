package main

// buildPromptScript returns the AppleScript source for collecting the
// Server URL and Agent Secret in the macOS one-click installer. When
// presetServerURL is non-empty (loaded from bas-agent-defaults.json, the
// console bundles it alongside the downloaded installer), the Server URL
// dialog is skipped entirely and that value is used as-is -- the operator
// is asked only for the Secret, matching the Linux/Windows CLI flows.
// Pure string construction (no os/exec) so it's testable without a Mac --
// only the osascript invocation itself lives in main_darwin.go.
func buildPromptScript(presetServerURL string) string {
	secretDialog := `set theSecret to text returned of (display dialog "Enter the Agent Secret:" default answer "" with title "BAS Agent Setup" buttons {"Cancel", "Install"} default button "Install" cancel button "Cancel" with hidden answer)`

	if presetServerURL != "" {
		return "set serverURL to " + appleScriptQuote(presetServerURL) + "\n" +
			secretDialog + "\n" +
			"serverURL & linefeed & theSecret"
	}

	serverDialog := `set serverURL to text returned of (display dialog "Enter the Server URL (from the console's Connection Config):" default answer "https://" with title "BAS Agent Setup" buttons {"Cancel", "Next"} default button "Next" cancel button "Cancel")`
	return serverDialog + "\n" + secretDialog + "\n" + "serverURL & linefeed & theSecret"
}
