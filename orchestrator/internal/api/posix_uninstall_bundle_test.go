package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

// uninstallFixture stages an agents dir holding the given agent files and lists in the signed manifest those whose
// name is in listed (with the right hash).
func uninstallFixture(t *testing.T, files map[string]string, listed []string) *Handler {
	t.Helper()
	dir := t.TempDir()
	lines := "deadbeef  something-else\n"
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range listed {
		lines += sha(files[name]) + "  " + name + "\n"
	}
	manifest := filepath.Join(dir, "BINARIES.sha256")
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

func linuxAgents() (map[string]string, []string) {
	f := map[string]string{"bas-agent-linux-amd64": "LIN-AMD", "bas-agent-linux-arm64": "LIN-ARM"}
	return f, []string{"bas-agent-linux-amd64", "bas-agent-linux-arm64"}
}

func macAgents() (map[string]string, []string) {
	f := map[string]string{"bas-agent-darwin-amd64": "MAC-AMD", "bas-agent-darwin-arm64": "MAC-ARM"}
	return f, []string{"bas-agent-darwin-amd64", "bas-agent-darwin-arm64"}
}

// ---- Linux ------------------------------------------------------------------------------------------------

func untar(t *testing.T, run []byte) map[string]string {
	t.Helper()
	marker := []byte("\n__ARCHIVE_BELOW__\n")
	i := bytes.Index(run, marker)
	if i < 0 {
		t.Fatal("no archive marker")
	}
	gz, err := gzip.NewReader(bytes.NewReader(run[i+len(marker):]))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = string(b)
	}
}

func TestServeLinuxUninstall_CarriesBothVerifiedAgentsAndNoSecrets(t *testing.T) {
	f, listed := linuxAgents()
	h := uninstallFixture(t, f, listed)
	rec := httptest.NewRecorder()
	h.serveLinuxUninstall(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "bas-agent-uninstall-linux.run") {
		t.Errorf("headers: %v", rec.Header())
	}
	if strings.Contains(rec.Body.String(), "TOPSECRET-AGENT-VALUE") {
		t.Fatal("the agent secret must not be in the download")
	}
	got := untar(t, rec.Body.Bytes())
	if got["bas-agent-linux-amd64"] != "LIN-AMD" || got["bas-agent-linux-arm64"] != "LIN-ARM" {
		t.Errorf("both verified agents are expected, got %v", keys(got))
	}
	if !strings.Contains(got["agents.sha256"], sha("LIN-AMD")+"  bas-agent-linux-amd64") {
		t.Errorf("agents.sha256 = %q", got["agents.sha256"])
	}
}

func keys(m map[string]string) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}

func TestServeUninstall_RefusesTamperedUnlistedMissingOrUnverifiable(t *testing.T) {
	serve := map[string]func(*Handler, *httptest.ResponseRecorder){
		"linux": func(h *Handler, rec *httptest.ResponseRecorder) { h.serveLinuxUninstall(rec, httptest.NewRequest(http.MethodGet, "/x", nil)) },
		"mac":   func(h *Handler, rec *httptest.ResponseRecorder) { h.serveMacUninstall(rec, httptest.NewRequest(http.MethodGet, "/x", nil)) },
	}
	for osName, call := range serve {
		agents := linuxAgents
		first := "bas-agent-linux-amd64"
		if osName == "mac" {
			agents, first = macAgents, "bas-agent-darwin-amd64"
		}
		t.Run(osName+"/tampered", func(t *testing.T) {
			f, listed := agents()
			h := uninstallFixture(t, f, listed)
			_ = os.WriteFile(filepath.Join(agentArtifactDir, first), []byte("TAMPERED"), 0o755)
			rec := httptest.NewRecorder()
			call(h, rec)
			if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Header().Get("Content-Type"), "octet") || strings.Contains(rec.Header().Get("Content-Type"), "zip") {
				t.Fatalf("status %d, nothing may be served", rec.Code)
			}
		})
		t.Run(osName+"/unlisted", func(t *testing.T) {
			f, listed := agents()
			h := uninstallFixture(t, f, listed[1:])
			rec := httptest.NewRecorder()
			call(h, rec)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status %d", rec.Code)
			}
		})
		t.Run(osName+"/missing", func(t *testing.T) {
			f, listed := agents()
			delete(f, first)
			h := uninstallFixture(t, f, listed)
			rec := httptest.NewRecorder()
			call(h, rec)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status %d", rec.Code)
			}
		})
		t.Run(osName+"/no-manifest", func(t *testing.T) {
			rec := httptest.NewRecorder()
			call(&Handler{}, rec)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status %d", rec.Code)
			}
		})
	}
}

const uninstallFakeAgent = `#!/bin/sh
printf 'AGENT %s keep=%s\n' "$*" "${BAS_UNINSTALL_KEEP_DATA:-}" >> "$AGENT_LOG"
echo "fake uninstall output"
exit "${FAKE_UNINSTALL_EXIT:-0}"
`

func runLinuxUninstall(t *testing.T, env map[string]string, mutate func(files map[string]string)) (out, agentLog string, code int) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	root := t.TempDir()
	files := map[string][]byte{}
	arch := map[string]string{"bas-agent-linux-amd64": uninstallFakeAgent, "bas-agent-linux-arm64": uninstallFakeAgent}
	var sums strings.Builder
	for n, c := range arch {
		files[n] = []byte(c)
		s := sha256.Sum256([]byte(c))
		sums.WriteString(hex.EncodeToString(s[:]) + "  " + n + "\n")
	}
	run, err := buildLinuxUninstallRun(files)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		m := map[string]string{}
		mutate(m)
		if m["corrupt"] != "" {
			files[m["corrupt"]] = []byte("#!/bin/sh\nexit 0\n")
			run = rebuildWithSums(t, files, sums.String())
		}
	}
	shims := filepath.Join(root, "shims")
	_ = os.MkdirAll(shims, 0o755)
	_ = os.WriteFile(filepath.Join(shims, "id"), []byte("#!/bin/sh\necho ${FAKE_UID:-0}\n"), 0o755)
	_ = os.WriteFile(filepath.Join(shims, "uname"), []byte("#!/bin/sh\necho ${FAKE_UNAME:-x86_64}\n"), 0o755)
	script := filepath.Join(root, "u.run")
	_ = os.WriteFile(script, run, 0o755)
	logf := filepath.Join(root, "agent.log")
	cmd := exec.Command(bash, filepath.ToSlash(script))
	cmd.Env = append(os.Environ(), "PATH="+filepath.ToSlash(shims)+string(os.PathListSeparator)+os.Getenv("PATH"), "AGENT_LOG="+filepath.ToSlash(logf))
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	o, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	b, _ := os.ReadFile(logf)
	return string(o), string(b), code
}

// rebuildWithSums packs the given files but keeps the ORIGINAL hashes, as a damaged download would.
func rebuildWithSums(t *testing.T, files map[string][]byte, sums string) []byte {
	t.Helper()
	run, err := buildLinuxUninstallRunWithSums(files, sums)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func TestLinuxUninstallRun_RunsTheAgentsUninstallForThisCPU(t *testing.T) {
	out, log, code := runLinuxUninstall(t, nil, nil)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, log)
	}
	if !strings.Contains(log, "AGENT --uninstall") || strings.Contains(log, "keep=1") {
		t.Errorf("a real uninstall removes everything:\n%s", log)
	}
	if !strings.Contains(strings.ToLower(out), "removed") {
		t.Errorf("the result must be stated:\n%s", out)
	}
}

func TestLinuxUninstallRun_RefusesToRunWithoutRootOrOnAnUnknownCPU(t *testing.T) {
	out, log, code := runLinuxUninstall(t, map[string]string{"FAKE_UID": "1000"}, nil)
	if code == 0 || log != "" || !strings.Contains(out, "root") {
		t.Errorf("non-root must be refused before anything runs (exit %d): %s %s", code, out, log)
	}
	out, log, code = runLinuxUninstall(t, map[string]string{"FAKE_UNAME": "riscv64"}, nil)
	if code == 0 || log != "" || !strings.Contains(strings.ToLower(out), "architecture") {
		t.Errorf("an unknown CPU must be refused (exit %d): %s %s", code, out, log)
	}
}

func TestLinuxUninstallRun_ADamagedAgentIsNeverRun(t *testing.T) {
	out, log, code := runLinuxUninstall(t, nil, func(m map[string]string) { m["corrupt"] = "bas-agent-linux-amd64" })
	if code == 0 || log != "" || !strings.Contains(strings.ToLower(out), "damaged") {
		t.Errorf("an agent that does not match its recorded hash must not run (exit %d): %s %s", code, out, log)
	}
}

func TestLinuxUninstallRun_AFailedUninstallIsReportedNotHidden(t *testing.T) {
	out, _, code := runLinuxUninstall(t, map[string]string{"FAKE_UNINSTALL_EXIT": "3"}, nil)
	if code == 0 || strings.Contains(strings.ToLower(out), "was removed") {
		t.Errorf("a failure must not claim success (exit %d): %s", code, out)
	}
}

// ---- macOS ------------------------------------------------------------------------------------------------

const macUnApp = "Audspect Agent Uninstall.app/"

func TestServeMacUninstall_IsAnAppWithBothVerifiedAgents(t *testing.T) {
	f, listed := macAgents()
	h := uninstallFixture(t, f, listed)
	rec := httptest.NewRecorder()
	h.serveMacUninstall(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "AudspectAgent-Uninstall-mac.zip") {
		t.Errorf("headers: %v", rec.Header())
	}
	files := readZip(t, rec.Body.Bytes())
	if files[macUnApp+"Contents/Resources/bas-agent-arm64"] != "MAC-ARM" || files[macUnApp+"Contents/Resources/bas-agent-x86_64"] != "MAC-AMD" {
		t.Errorf("both verified agents are expected: %v", keys(files))
	}
	if files[macUnApp+"Contents/MacOS/uninstall"] != string(macUninstallScriptSource) {
		t.Error("the bundle's program is not the embedded script")
	}
	if !strings.Contains(files[macUnApp+"Contents/Info.plist"], "<string>uninstall</string>") {
		t.Error("Info.plist must name the uninstall program")
	}
	if strings.Contains(rec.Body.String(), "TOPSECRET-AGENT-VALUE") {
		t.Fatal("no secret may be in the download")
	}
}

const uninstallOsascriptExtra = `` // the shared stand-in (macOsascriptShim) handles the confirm dialog

func runMacUninstall(t *testing.T, env map[string]string, mutate func(res string)) macRun {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	root := t.TempDir()
	zb, err := buildMacUninstallApp(map[string][]byte{"arm64": []byte(uninstallFakeAgent), "x86_64": []byte(uninstallFakeAgent)})
	if err != nil {
		t.Fatal(err)
	}
	unzipTo(t, zb, root)
	appDir := filepath.Join(root, "Audspect Agent Uninstall.app")
	res := filepath.Join(appDir, "Contents", "Resources")
	for _, p := range []string{filepath.Join(appDir, "Contents", "MacOS", "uninstall"), filepath.Join(res, "bas-agent-arm64"), filepath.Join(res, "bas-agent-x86_64")} {
		_ = os.Chmod(p, 0o755)
	}
	if mutate != nil {
		mutate(res)
	}
	shims := filepath.Join(root, "shims")
	_ = os.MkdirAll(shims, 0o755)
	w := func(n, b string) { _ = os.WriteFile(filepath.Join(shims, n), []byte(b), 0o755) }
	w("osascript", macOsascriptShim)
	w("xattr", "#!/bin/sh\necho \"xattr $*\" >> \"$LOG\"\n")
	w("sysctl", "#!/bin/sh\necho \"${FAKE_ARM:-1}\"\n")
	w("uname", "#!/bin/sh\necho \"${FAKE_UNAME:-arm64}\"\n")
	w("shasum", "#!/bin/sh\nshift 2\nsha256sum \"$@\"\n")
	tmp := filepath.Join(root, "tmp")
	_ = os.MkdirAll(tmp, 0o755)
	logf, agentLog := filepath.Join(root, "log.txt"), filepath.Join(root, "agent.txt")
	cmd := exec.Command("sh", filepath.ToSlash(filepath.Join(appDir, "Contents", "MacOS", "uninstall")))
	cmd.Env = append(os.Environ(), "PATH="+filepath.ToSlash(shims)+string(os.PathListSeparator)+os.Getenv("PATH"), "LOG="+logf, "AGENT_LOG="+agentLog, "TMPDIR="+tmp)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	o, err := cmd.CombinedOutput()
	r := macRun{tmp: tmp, out: string(o)}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	}
	if b, err := os.ReadFile(logf); err == nil {
		r.log = string(b)
	}
	if b, err := os.ReadFile(agentLog); err == nil {
		r.agentLog = string(b)
	}
	return r
}

func TestMacUninstallScript_ConfirmsThenRemovesThroughTheAdministratorPrompt(t *testing.T) {
	r := runMacUninstall(t, nil, nil)
	if r.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.code, r.log, r.agentLog)
	}
	if !strings.Contains(r.agentLog, "AGENT --uninstall") || strings.Contains(r.agentLog, "keep=1") {
		t.Errorf("the agent must be run with --uninstall and keep nothing:\n%s", r.agentLog)
	}
	if !strings.Contains(r.log, "administrator privileges") || !strings.Contains(r.log, "xattr -dr com.apple.quarantine") {
		t.Errorf("removal needs the administrator prompt and a cleared quarantine flag:\n%s", r.log)
	}
	if !strings.Contains(strings.ToLower(r.log), "were removed") {
		t.Errorf("the result must be stated:\n%s", r.log)
	}
	assertNothingLeftBehind(t, r)
}

func TestMacUninstallScript_CancellingTheConfirmationChangesNothing(t *testing.T) {
	r := runMacUninstall(t, map[string]string{"CANCEL_CONFIRM": "1"}, nil)
	if r.agentLog != "" || strings.Contains(r.log, "administrator privileges") {
		t.Errorf("nothing may run after cancel:\n%s\n%s", r.log, r.agentLog)
	}
	if r.code != 0 {
		t.Errorf("cancelling is not an error (exit %d)", r.code)
	}
}

func TestMacUninstallScript_PicksTheAgentForThisMac(t *testing.T) {
	r := runMacUninstall(t, map[string]string{"FAKE_UNAME": "x86_64", "FAKE_ARM": "0"}, nil)
	if !strings.Contains(r.agentLog, "AGENT --uninstall") {
		t.Fatalf("an Intel Mac must also be served:\n%s\n%s", r.log, r.agentLog)
	}
}

func TestMacUninstallScript_ADamagedAgentIsNeverRun(t *testing.T) {
	r := runMacUninstall(t, nil, func(res string) {
		_ = os.WriteFile(filepath.Join(res, "bas-agent-arm64"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	})
	if r.agentLog != "" || !strings.Contains(strings.ToLower(r.log), "damaged") {
		t.Errorf("an agent that does not match its recorded hash must not run:\n%s\n%s", r.log, r.agentLog)
	}
}

func TestMacUninstallScript_AFailedRemovalIsReportedNotHidden(t *testing.T) {
	r := runMacUninstall(t, map[string]string{"FAKE_UNINSTALL_EXIT": "3"}, nil)
	l := strings.ToLower(r.log)
	if r.code == 0 || strings.Contains(l, "were removed") || !strings.Contains(l, "not") {
		t.Errorf("a failure must not claim success (exit %d):\n%s", r.code, r.log)
	}
}

func TestMacUninstallScript_StaticSafetyProperties(t *testing.T) {
	s := string(macUninstallScriptSource)
	for _, must := range []string{"administrator privileges", "com.apple.quarantine", "trap ", `buttons {\"Cancel\", \"Remove\"}`} {
		if !strings.Contains(s, must) {
			t.Errorf("uninstall script lacks %q", must)
		}
	}
	for _, mustNot := range []string{"curl ", "sudo ", "rm -rf /"} {
		if strings.Contains(s, mustNot) {
			t.Errorf("uninstall script must not contain %q", mustNot)
		}
	}
}

// Both Mac apps carry the Audspect icon and name it in Info.plist, so Finder and the dialogs show the brand.
func TestMacApps_CarryTheAudspectIcon(t *testing.T) {
	setup, err := buildMacSetupApp([]byte("A"), []byte("{}"), testFP, "arm64", false)
	if err != nil {
		t.Fatal(err)
	}
	un, err := buildMacUninstallApp(map[string][]byte{"arm64": []byte("A"), "x86_64": []byte("B")})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		zip []byte
		app string
	}{"setup": {setup, macApp}, "uninstall": {un, macUnApp}} {
		files := readZip(t, c.zip)
		icon := files[c.app+"Contents/Resources/AppIcon.icns"]
		if len(icon) < 1000 || !strings.HasPrefix(icon, "icns") {
			t.Errorf("%s app: AppIcon.icns missing or not an icns file (%d bytes)", name, len(icon))
		}
		if !strings.Contains(files[c.app+"Contents/Info.plist"], "<key>CFBundleIconFile</key><string>AppIcon</string>") {
			t.Errorf("%s app: Info.plist does not name the icon", name)
		}
	}
}
