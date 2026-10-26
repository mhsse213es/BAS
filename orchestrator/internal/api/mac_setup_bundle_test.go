package api

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/cmdsigning"
	"github.com/audspect/bas/internal/integrity"
)

const macApp = "Audspect Agent Setup.app/"

func unzipTo(t *testing.T, b []byte, dir string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		p := filepath.Join(dir, filepath.FromSlash(f.Name))
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(p, 0o755)
			continue
		}
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		if err := os.WriteFile(p, data, f.Mode()|0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBuildMacSetupApp_IsASelfContainedAppBundle(t *testing.T) {
	zb, err := buildMacSetupApp([]byte("AGENT-BYTES"), []byte(`{"version":1}`), testFP, "arm64", false)
	if err != nil {
		t.Fatal(err)
	}
	files := readZip(t, zb)
	sum := sha256.Sum256([]byte("AGENT-BYTES"))
	for name, want := range map[string]string{
		macApp + "Contents/Resources/bas-agent":              "AGENT-BYTES",
		macApp + "Contents/Resources/deployment.json":        `{"version":1}`,
		macApp + "Contents/Resources/arch":                   "arm64\n",
		macApp + "Contents/Resources/agent.sha256":           hex.EncodeToString(sum[:]) + "\n",
		macApp + "Contents/Resources/deployment.fingerprint": testFP + "\n",
	} {
		if files[name] != want {
			t.Errorf("%s = %q, want %q", name, files[name], want)
		}
	}
	if !strings.Contains(files[macApp+"Contents/Info.plist"], "<string>setup</string>") {
		t.Error("Info.plist must name the setup script as the bundle executable")
	}
	if files[macApp+"Contents/MacOS/setup"] != string(macSetupScriptSource) {
		t.Error("the bundle's setup script is not the embedded one")
	}
	if _, ok := files[macApp+"Contents/Resources/enrollment-token.required"]; ok {
		t.Error("a secret-mode server must not ask for a token")
	}
	// the executable bits must survive the zip, or double-click does nothing
	zr, _ := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	for _, f := range zr.File {
		if (f.Name == macApp+"Contents/MacOS/setup" || f.Name == macApp+"Contents/Resources/bas-agent") && f.Mode()&0o111 == 0 {
			t.Errorf("%s lost its executable bit", f.Name)
		}
	}
}

func TestBuildMacSetupApp_TokenMarkerOnlyWhenTheServerIssuesTokens(t *testing.T) {
	zb, err := buildMacSetupApp([]byte("A"), []byte("{}"), testFP, "amd64", true)
	if err != nil {
		t.Fatal(err)
	}
	files := readZip(t, zb)
	if _, ok := files[macApp+"Contents/Resources/enrollment-token.required"]; !ok {
		t.Error("a token-mode server must mark the bundle so the app asks for the token")
	}
	if files[macApp+"Contents/Resources/arch"] != "x86_64\n" {
		t.Errorf("amd64 must be recorded as x86_64, got %q", files[macApp+"Contents/Resources/arch"])
	}
}

func TestBuildMacSetupApp_RefusesBadInput(t *testing.T) {
	if _, err := buildMacSetupApp([]byte("A"), []byte("{}"), "nothex", "arm64", false); err == nil {
		t.Error("a malformed fingerprint must be refused")
	}
	if _, err := buildMacSetupApp([]byte("A"), []byte("{}"), testFP, "ppc", false); err == nil {
		t.Error("an unknown architecture must be refused")
	}
	if _, err := buildMacSetupApp(nil, []byte("{}"), testFP, "arm64", false); err == nil {
		t.Error("an empty agent must be refused")
	}
}

func macFixture(t *testing.T, arch, content, manifestHash string) *Handler {
	t.Helper()
	dir := t.TempDir()
	name := "bas-agent-darwin-" + arch
	if content != "" {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	manifest := filepath.Join(dir, "BINARIES.sha256")
	lines := "deadbeef  something-else\n"
	if manifestHash != "" {
		lines += manifestHash + "  " + name + "\n"
	}
	if err := os.WriteFile(manifest, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := agentArtifactDir
	agentArtifactDir = dir
	t.Cleanup(func() { agentArtifactDir = prev })
	sk, err := cmdsigning.LoadOrGenerateSigningKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := (&Handler{agentSecret: "TOPSECRET-AGENT-VALUE"}).WithAdvertisedPorts(9443, 9444).WithCommandSigningKey(sk)
	return h.WithManifest(integrity.LoadManifest(manifest))
}

func TestServeMacSetup_ServesTheVerifiedAgentInASignedConfigApp(t *testing.T) {
	h := macFixture(t, "arm64", "MAC-AGENT", sha("MAC-AGENT"))
	rec := httptest.NewRecorder()
	h.serveMacSetup(rec, httptest.NewRequest(http.MethodGet, "https://bas.example.com:8443/api/agents/download/darwin-arm64-setup", nil), "arm64")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/zip" || !strings.Contains(rec.Header().Get("Content-Disposition"), "AudspectAgent-Setup-mac-arm64.zip") {
		t.Fatalf("headers: %v", rec.Header())
	}
	if strings.Contains(rec.Body.String(), "TOPSECRET-AGENT-VALUE") {
		t.Fatal("the agent secret must not be in the download")
	}
	files := readZip(t, rec.Body.Bytes())
	if files[macApp+"Contents/Resources/bas-agent"] != "MAC-AGENT" {
		t.Error("the agent in the app is not the verified artifact")
	}
	if !strings.Contains(files[macApp+"Contents/Resources/deployment.json"], `"signature"`) {
		t.Error("the app must carry the signed deployment configuration")
	}
	if len(strings.TrimSpace(files[macApp+"Contents/Resources/deployment.fingerprint"])) != 64 {
		t.Error("the app must carry the signing fingerprint")
	}
}

func TestServeMacSetup_RefusesTamperedUnlistedOrMissingAgents(t *testing.T) {
	cases := map[string]struct {
		content, hash string
		want          int
	}{
		"hash mismatch":   {"TAMPERED", sha("MAC-AGENT"), http.StatusInternalServerError},
		"not in manifest": {"MAC-AGENT", "", http.StatusInternalServerError},
		"file missing":    {"", sha("MAC-AGENT"), http.StatusNotFound},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := macFixture(t, "amd64", c.content, c.hash)
			rec := httptest.NewRecorder()
			h.serveMacSetup(rec, httptest.NewRequest(http.MethodGet, "/x", nil), "amd64")
			if rec.Code != c.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, c.want, rec.Body.String())
			}
			if strings.Contains(rec.Header().Get("Content-Type"), "zip") {
				t.Fatal("nothing may be served")
			}
		})
	}
}

func TestServeMacSetup_RequiresManifestAndSigningKey(t *testing.T) {
	h := macFixture(t, "arm64", "MAC-AGENT", sha("MAC-AGENT"))
	noManifest := (&Handler{}).WithAdvertisedPorts(9443, 9444).WithCommandSigningKey(h.signingKey)
	rec := httptest.NewRecorder()
	noManifest.serveMacSetup(rec, httptest.NewRequest(http.MethodGet, "/x", nil), "arm64")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no manifest: status %d, want 503 (the agent is never served unverified)", rec.Code)
	}
	noKey := (&Handler{}).WithManifest(h.manifest)
	rec = httptest.NewRecorder()
	noKey.serveMacSetup(rec, httptest.NewRequest(http.MethodGet, "/x", nil), "arm64")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no signing key: status %d, want 503", rec.Code)
	}
}

func TestServeMacSetup_TokenModeAddsTheMarker(t *testing.T) {
	h := macFixture(t, "arm64", "MAC-AGENT", sha("MAC-AGENT")).WithEnrollmentMode(EnrollmentModeToken)
	rec := httptest.NewRecorder()
	h.serveMacSetup(rec, httptest.NewRequest(http.MethodGet, "/x", nil), "arm64")
	if _, ok := readZip(t, rec.Body.Bytes())[macApp+"Contents/Resources/enrollment-token.required"]; !ok {
		t.Error("token-mode server must mark the app")
	}
}

func TestMacSetupScript_StaticSafetyProperties(t *testing.T) {
	s := string(macSetupScriptSource)
	for _, must := range []string{
		"--secret-stdin",              // the secret goes in on stdin
		"hidden answer",               // typed into a masked dialog
		"administrator privileges",    // the native macOS admin prompt
		"com.apple.quarantine",        // the unsigned agent must be runnable after the one Open Anyway
		"--config-fingerprint",        // the signed deployment config is verified
		"--enrollment-token-file",     // a token never goes on a command line
		"trap ",                       // the secret file is removed however the script ends
	} {
		if !strings.Contains(s, must) {
			t.Errorf("setup script lacks %q", must)
		}
	}
	for _, mustNot := range []string{"--secret ", "--secret=", "curl ", "sudo "} {
		if strings.Contains(s, mustNot) {
			t.Errorf("setup script must not contain %q", mustNot)
		}
	}
	if !strings.HasPrefix(s, "#!/bin/sh") {
		t.Error("the setup script must run under /bin/sh")
	}
}

// ---- behavioural run of the real script with stand-ins for osascript and the agent ----------------------

const macFakeAgent = `#!/bin/sh
# stand-in for the real agent: records what it was given and answers with a chosen exit code
printf 'AGENT %s\n' "$*" >> "$AGENT_LOG"
mode=""; tokfile=""
while [ $# -gt 0 ]; do
  case "$1" in
    --preflight) mode=preflight ;;
    --install) mode=install ;;
    --enrollment-token-file) tokfile="$2"; shift ;;
  esac
  shift
done
secret=$(cat)
printf 'STDIN %s %s\n' "$mode" "$secret" >> "$AGENT_LOG"
if [ -n "$tokfile" ]; then printf 'TOKENFILE %s\n' "$(cat "$tokfile")" >> "$AGENT_LOG"; rm -f "$tokfile"; fi
if [ "$mode" = preflight ]; then exit "${FAKE_PREFLIGHT_EXIT:-0}"; fi
exit "${FAKE_INSTALL_EXIT:-0}"
`

const macOsascriptShim = `#!/bin/sh
echo "osascript $*" >> "$LOG"
all="$*"
last=""; prev=""
for a in "$@"; do prev="$last"; last="$a"; done
case "$all" in
  *"administrator privileges"*)
    out=$(sh -c "$last" 2>&1); rc=$?
    if [ $rc -ne 0 ]; then echo "execution error: $out ($rc)" >&2; exit 1; fi
    exit 0 ;;
  *"hidden answer"*)
    case "$all" in
      *oken*) if [ -n "${CANCEL_TOKEN:-}" ]; then echo "execution error: User canceled. (-128)" >&2; exit 1; fi; printf '%s\n' "$FAKE_TOKEN" ;;
      *)      if [ -n "${CANCEL_SECRET:-}" ]; then echo "execution error: User canceled. (-128)" >&2; exit 1; fi; printf '%s\n' "$FAKE_SECRET" ;;
    esac
    exit 0 ;;
  *'"Remove"'*)
    if [ -n "${CANCEL_CONFIRM:-}" ]; then echo "execution error: User canceled. (-128)" >&2; exit 1; fi
    exit 0 ;;
  *"display dialog"*)
    echo "DIALOG: $all" >> "$LOG"; exit 0 ;;
esac
exit 0
`

type macRun struct {
	log, agentLog, tmp string
	out                string
	code               int
}

func runMacScript(t *testing.T, tokenRequired bool, arch string, env map[string]string, mutate func(appDir string)) macRun {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	root := t.TempDir()
	zb, err := buildMacSetupApp([]byte(macFakeAgent), []byte(`{"version":1}`), testFP, arch, tokenRequired)
	if err != nil {
		t.Fatal(err)
	}
	unzipTo(t, zb, root)
	appDir := filepath.Join(root, "Audspect Agent Setup.app")
	for _, p := range []string{"Contents/MacOS/setup", "Contents/Resources/bas-agent"} {
		_ = os.Chmod(filepath.Join(appDir, filepath.FromSlash(p)), 0o755)
	}
	if mutate != nil {
		mutate(appDir)
	}
	shims := filepath.Join(root, "shims")
	_ = os.MkdirAll(shims, 0o755)
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(shims, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("osascript", macOsascriptShim)
	write("xattr", "#!/bin/sh\necho \"xattr $*\" >> \"$LOG\"\n")
	write("sysctl", "#!/bin/sh\necho \"${FAKE_ARM:-1}\"\n")
	write("uname", "#!/bin/sh\necho \"${FAKE_UNAME:-arm64}\"\n")
	write("shasum", "#!/bin/sh\nshift 2\nsha256sum \"$@\"\n")
	tmp := filepath.Join(root, "tmp")
	_ = os.MkdirAll(tmp, 0o755)
	logf := filepath.Join(root, "log.txt")
	agentLog := filepath.Join(root, "agent.txt")

	cmd := exec.Command("sh", filepath.ToSlash(filepath.Join(appDir, "Contents", "MacOS", "setup")))
	cmd.Env = append(os.Environ(),
		"PATH="+shims+string(os.PathListSeparator)+os.Getenv("PATH"),
		"LOG="+logf, "AGENT_LOG="+agentLog, "TMPDIR="+tmp,
		"FAKE_SECRET=S3cr3t-VALUE-9f2", "FAKE_TOKEN=bas_enr_TOKEN-VALUE-77",
		"BAS_SETUP_PLIST="+filepath.Join(root, "no-such.plist"),
	)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	r := macRun{tmp: tmp, out: string(out), code: code}
	if b, err := os.ReadFile(logf); err == nil {
		r.log = string(b)
	}
	if b, err := os.ReadFile(agentLog); err == nil {
		r.agentLog = string(b)
	}
	return r
}

const macSecretValue = "S3cr3t-VALUE-9f2"
const macTokenValue = "bas_enr_TOKEN-VALUE-77"

func assertNothingLeftBehind(t *testing.T, r macRun) {
	t.Helper()
	left, _ := os.ReadDir(r.tmp)
	if len(left) != 0 {
		names := []string{}
		for _, e := range left {
			names = append(names, e.Name())
		}
		t.Errorf("staging files left behind (they held the secret): %v", names)
	}
}

func TestMacSetupScript_InstallsAskingOnlyForTheSecretAndNeverPutsItOnACommandLine(t *testing.T) {
	r := runMacScript(t, false, "arm64", nil, nil)
	if r.code != 0 {
		t.Fatalf("exit %d\nlog:\n%s\nagent:\n%s\nout:\n%s", r.code, r.log, r.agentLog, r.out)
	}
	if strings.Contains(r.log, macSecretValue) || strings.Contains(r.out, macSecretValue) {
		t.Error("the secret appeared in an osascript argument or in the output")
	}
	for _, line := range strings.Split(r.agentLog, "\n") {
		if strings.HasPrefix(line, "AGENT ") && strings.Contains(line, macSecretValue) {
			t.Errorf("the secret appeared in the agent's arguments: %s", line)
		}
	}
	if !strings.Contains(r.agentLog, "STDIN preflight "+macSecretValue) || !strings.Contains(r.agentLog, "STDIN install "+macSecretValue) {
		t.Errorf("the agent must receive the secret on stdin for the check and for the install:\n%s", r.agentLog)
	}
	if strings.Count(r.log, "hidden answer") != 1 {
		t.Errorf("exactly one prompt (the secret) is expected, got:\n%s", r.log)
	}
	if !strings.Contains(r.agentLog, "--config-fingerprint "+testFP) || !strings.Contains(r.agentLog, "--install") {
		t.Errorf("the install must use the signed configuration and its fingerprint:\n%s", r.agentLog)
	}
	if !strings.Contains(r.log, "xattr -dr com.apple.quarantine") {
		t.Error("the quarantine flag must be cleared before the agent is run")
	}
	if !strings.Contains(r.log, "DIALOG: ") || !strings.Contains(strings.ToLower(r.log), "installed") {
		t.Errorf("a success message is expected:\n%s", r.log)
	}
	assertNothingLeftBehind(t, r)
}

func TestMacSetupScript_AlreadyInstalledAsksForNothingAndChangesNothing(t *testing.T) {
	r := runMacScript(t, false, "arm64", nil, func(app string) {
		_ = os.WriteFile(filepath.Join(filepath.Dir(app), "present.plist"), []byte("x"), 0o644)
	})
	_ = r
	root := t.TempDir()
	_ = root
	r2 := runMacScriptWithPlist(t)
	if strings.Contains(r2.log, "hidden answer") || r2.agentLog != "" {
		t.Errorf("an installed agent keeps its enrolment: no prompt and no agent run expected\nlog:\n%s\nagent:\n%s", r2.log, r2.agentLog)
	}
	if !strings.Contains(strings.ToLower(r2.log), "already installed") {
		t.Errorf("the user must be told it is already installed:\n%s", r2.log)
	}
}

// runMacScriptWithPlist points the already-installed check at a file that exists.
func runMacScriptWithPlist(t *testing.T) macRun {
	t.Helper()
	plist := filepath.Join(t.TempDir(), "present.plist")
	_ = os.WriteFile(plist, []byte("x"), 0o644)
	return runMacScript(t, false, "arm64", map[string]string{"BAS_SETUP_PLIST": plist}, nil)
}

func TestMacSetupScript_ARejectedSecretIsExplainedAndNothingIsInstalled(t *testing.T) {
	r := runMacScript(t, false, "arm64", map[string]string{"FAKE_PREFLIGHT_EXIT": "22"}, nil)
	if strings.Contains(r.agentLog, "STDIN install") {
		t.Error("the install must not run when the check failed")
	}
	if !strings.Contains(strings.ToLower(r.log), "secret") || !strings.Contains(strings.ToLower(r.log), "rejected") {
		t.Errorf("the message must say the server rejected the secret:\n%s", r.log)
	}
	if r.code == 0 {
		t.Error("a failed install must not exit 0")
	}
	assertNothingLeftBehind(t, r)
}

func TestMacSetupScript_AConnectionProblemIsNotReportedAsABadSecret(t *testing.T) {
	r := runMacScript(t, false, "arm64", map[string]string{"FAKE_PREFLIGHT_EXIT": "21"}, nil)
	l := strings.ToLower(r.log)
	if !strings.Contains(l, "could not be reached") || strings.Contains(l, "rejected the agent secret") {
		t.Errorf("an unreachable server must be reported as such:\n%s", r.log)
	}
}

func TestMacSetupScript_CancellingTheSecretPromptEndsQuietly(t *testing.T) {
	r := runMacScript(t, false, "arm64", map[string]string{"CANCEL_SECRET": "1"}, nil)
	if r.agentLog != "" {
		t.Errorf("nothing may run after cancel:\n%s", r.agentLog)
	}
	if strings.Contains(strings.ToLower(r.log), "failed") {
		t.Errorf("cancelling is not an error:\n%s", r.log)
	}
	assertNothingLeftBehind(t, r)
}

func TestMacSetupScript_TokenModeAsksForTheTokenAndPassesItThroughAFile(t *testing.T) {
	r := runMacScript(t, true, "arm64", nil, nil)
	if r.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.code, r.log, r.agentLog)
	}
	if strings.Count(r.log, "hidden answer") != 2 {
		t.Errorf("secret and token are both asked for:\n%s", r.log)
	}
	if strings.Contains(r.log, macTokenValue) || strings.Contains(r.agentLog, "AGENT"+" "+macTokenValue) {
		t.Error("the token must never be in an argument list")
	}
	for _, line := range strings.Split(r.agentLog, "\n") {
		if strings.HasPrefix(line, "AGENT ") && strings.Contains(line, macTokenValue) {
			t.Errorf("token on the agent's command line: %s", line)
		}
	}
	if !strings.Contains(r.agentLog, "--enrollment-token-file") || !strings.Contains(r.agentLog, "TOKENFILE "+macTokenValue) {
		t.Errorf("the token must reach the agent through a file:\n%s", r.agentLog)
	}
	assertNothingLeftBehind(t, r)
}

func TestMacSetupScript_ARefusedTokenIsExplainedSeparatelyFromAConnectionFailure(t *testing.T) {
	r := runMacScript(t, true, "arm64", map[string]string{"FAKE_INSTALL_EXIT": "26"}, nil)
	l := strings.ToLower(r.log)
	if !strings.Contains(l, "token") || !strings.Contains(l, "refused") {
		t.Errorf("exit 26 means the server refused the token:\n%s", r.log)
	}
	r = runMacScript(t, true, "arm64", map[string]string{"FAKE_INSTALL_EXIT": "27"}, nil)
	l = strings.ToLower(r.log)
	if !strings.Contains(l, "not a token problem") {
		t.Errorf("exit 27 is a connection problem, not a token problem:\n%s", r.log)
	}
}

func TestMacSetupScript_MissingConfigurationStopsBeforeAskingForAnything(t *testing.T) {
	r := runMacScript(t, false, "arm64", nil, func(app string) {
		_ = os.Remove(filepath.Join(app, "Contents", "Resources", "deployment.json"))
	})
	if strings.Contains(r.log, "hidden answer") || r.agentLog != "" {
		t.Errorf("without the signed configuration nothing may be asked or run:\n%s\n%s", r.log, r.agentLog)
	}
	if r.code == 0 {
		t.Error("must not exit 0")
	}
}

func TestMacSetupScript_AnAppleSiliconAppOnAnIntelMacIsRefused(t *testing.T) {
	r := runMacScript(t, false, "arm64", map[string]string{"FAKE_UNAME": "x86_64", "FAKE_ARM": "0"}, nil)
	if strings.Contains(r.log, "hidden answer") || r.agentLog != "" {
		t.Errorf("the wrong-architecture app must stop before asking for anything:\n%s", r.log)
	}
	if !strings.Contains(strings.ToLower(r.log), "apple silicon") {
		t.Errorf("the message must say which Mac this app is for:\n%s", r.log)
	}
}

func TestMacSetupScript_ACorruptedAgentIsNeverRun(t *testing.T) {
	r := runMacScript(t, false, "arm64", nil, func(app string) {
		_ = os.WriteFile(filepath.Join(app, "Contents", "Resources", "bas-agent"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	})
	if r.agentLog != "" {
		t.Errorf("an agent that does not match its recorded hash must not run:\n%s", r.agentLog)
	}
	if !strings.Contains(strings.ToLower(r.log), "damaged") && !strings.Contains(strings.ToLower(r.log), "changed") {
		t.Errorf("the user must be told the download is damaged:\n%s", r.log)
	}
}
