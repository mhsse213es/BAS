//go:build darwin

package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// main dispatches between the two phases of a one-click macOS install:
//
//  1. Unprivileged (no args): collect Server URL + Secret via native
//     dialogs, then re-invoke this same binary as --do-install through
//     AppleScript's "with administrator privileges" -- the native macOS
//     admin password prompt. Placing the agent binary at /usr/local/bin and
//     registering the launchd daemon both require root, but the operator
//     never touches Terminal.
//  2. Privileged (--do-install <config-path>): runs as root via that
//     elevation. Reads the Server URL + Secret back from the private temp
//     file the unprivileged phase wrote (never passed as literal command-
//     line text, so the secret never appears in a shell string or a
//     process listing), validates connectivity, extracts the embedded
//     agent binary, fetches the deployment CA, and runs --install.
//
// parsedEmbeddedConfig is resolved once, in main(), before either phase
// runs -- see main.go's identical var for the Windows installer and
// embedconfig.go for extraction/validation. Both phases of this binary
// (the re-exec through --do-install still runs the same executable) see
// the same parsed value.
var parsedEmbeddedConfig embeddedConfig

func main() {
	cfg, err := extractEmbeddedConfig([]byte(embeddedConfigSlot))
	if err != nil {
		showAlert("BAS Agent Setup failed", "This installer's embedded configuration is invalid or corrupted: "+err.Error()+". Re-download the installer from the console. Do not run this copy.")
		return
	}
	parsedEmbeddedConfig = cfg

	args := os.Args[1:]
	if len(args) >= 1 && args[0] == "--do-install" {
		runPrivilegedInstall(args[1:])
		return
	}
	runSetupWizard()
}

func runSetupWizard() {
	serverURL, secret, ok := promptForServerAndSecret(parsedEmbeddedConfig.ServerURL)
	if !ok {
		return // cancelled or dismissed -- exit quietly, no error dialog
	}

	configPath, err := writeInstallConfig(serverURL, secret)
	if err != nil {
		showAlert("BAS Agent Setup failed", err.Error())
		return
	}
	defer os.Remove(configPath)

	selfPath, err := os.Executable()
	if err != nil {
		showAlert("BAS Agent Setup failed", "could not determine installer path: "+err.Error())
		return
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		showAlert("BAS Agent Setup failed", "could not resolve installer path: "+err.Error())
		return
	}

	shellCmd := shQuote(selfPath) + " --do-install " + shQuote(configPath)
	script := "do shell script " + appleScriptQuote(shellCmd) +
		` with administrator privileges with prompt "BAS Agent needs administrator access to install."`
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		if isUserCancelled(out) {
			return
		}
		showAlert("BAS Agent install failed", strings.TrimSpace(string(out)))
		return
	}
	showAlert("BAS Agent installed", "The agent is now running and will appear in the console's Agents tab within about 30 seconds.")
}

// runPrivilegedInstall is the root-elevated phase. args[0] is the config
// file path written by writeInstallConfig.
func runPrivilegedInstall(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "error: --do-install requires a config file path")
		os.Exit(1)
	}
	configPath := args[0]
	serverURL, secret, err := readInstallConfig(configPath)
	os.Remove(configPath) // best-effort cleanup either way -- it holds the secret
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// An embedded CA root (patched into this exact binary by the
	// orchestrator's download handler, after it verified the base
	// artifact against the signed manifest) lets validateEnrollment
	// actually verify the server's certificate chain instead of skipping
	// verification -- see trustingHTTPClient's doc comment in ca_fetch.go.
	var caPool *x509.CertPool
	if parsedEmbeddedConfig.CARootPEM != "" {
		caPool = x509.NewCertPool()
		if !caPool.AppendCertsFromPEM([]byte(parsedEmbeddedConfig.CARootPEM)) {
			fmt.Fprintln(os.Stderr, "error: embedded CA root could not be loaded")
			os.Exit(1)
		}
	}

	fmt.Println("[1/4] Validating server connectivity and secret...")
	if err := validateEnrollment(serverURL, secret, caPool); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[1/4] Server validated OK.")

	tmpDir, err := os.MkdirTemp("", "bas-agent-install-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	fmt.Println("[2/4] Extracting agent binary...")
	agentPath := filepath.Join(tmpDir, "bas-agent")
	if err := os.WriteFile(agentPath, agentData, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error: write agent binary: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[3/4] Placing deployment CA...")
	var caPath string
	if parsedEmbeddedConfig.CARootPEM != "" {
		caPath, err = writeEmbeddedCA([]byte(parsedEmbeddedConfig.CARootPEM), tmpDir)
	} else {
		caPath, err = fetchDeploymentCA(serverURL, tmpDir)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[4/4] Installing launchd daemon...")
	cmd := exec.Command(agentPath, "--install",
		"--server", serverURL,
		"--secret", secret,
		"--env", "Production",
		"--ca-root", caPath,
	)
	out, err := cmd.CombinedOutput()
	fmt.Print(string(out))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: install failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] BAS Agent installed successfully.")
}

// promptForServerAndSecret shows the operator's inputs: the Server URL
// (skipped, using presetServerURL, when bas-agent-defaults.json supplied
// one) and the Agent Secret, always asked (the Env label is fixed to
// "Production" and never asked for). Returns ok=false if either dialog
// was cancelled -- callers should exit quietly in that case, not show an
// error.
func promptForServerAndSecret(presetServerURL string) (serverURL, secret string, ok bool) {
	out, err := exec.Command("osascript", "-e", buildPromptScript(presetServerURL)).Output()
	if err != nil {
		return "", "", false
	}
	lines := strings.SplitN(strings.TrimRight(string(out), "\n"), "\n", 2)
	if len(lines) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(lines[0]), lines[1], true
}

func showAlert(title, message string) {
	script := "display alert " + appleScriptQuote(title) + " message " + appleScriptQuote(message)
	_ = exec.Command("osascript", "-e", script).Run()
}

// isUserCancelled reports whether osascript's combined output indicates the
// operator dismissed the administrator-privileges password prompt, which
// AppleScript surfaces as error -128 ("User canceled.") -- that is not a
// failure to report, just an exit.
func isUserCancelled(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "User canceled") || strings.Contains(s, "(-128)")
}
