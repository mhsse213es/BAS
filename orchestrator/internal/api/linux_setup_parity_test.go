package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/integrity"
)

func TestLinuxSetupScriptFor_ChoosesTheAgentByArchitecture(t *testing.T) {
	s, err := buildLinuxSetupScriptFor("10.0.0.5", 9445, 9443, 9543, "arm64", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(s), "--agent ./bas-agent-linux-arm64") {
		t.Errorf("the ARM64 setup must install the ARM64 agent:\n%s", s)
	}
	if _, err := buildLinuxSetupScriptFor("10.0.0.5", 9445, 9443, 9543, "mips", false); err == nil {
		t.Error("an unknown architecture must be refused")
	}
}

func TestLinuxSetupScriptFor_TokenModeMarksTheInstallAsNeedingAToken(t *testing.T) {
	with, _ := buildLinuxSetupScriptFor("10.0.0.5", 9445, 9443, 9543, "amd64", true)
	without, _ := buildLinuxSetupScriptFor("10.0.0.5", 9445, 9443, 9543, "amd64", false)
	if !strings.Contains(string(with), "BAS_TOKEN_REQUIRED=1") {
		t.Error("a token-mode server must make the installer require a token")
	}
	if strings.Contains(string(without), "BAS_TOKEN_REQUIRED") {
		t.Error("a secret-mode server must not ask for a token")
	}
	if !strings.Contains(string(with), "BAS_SERVER_HOST=10.0.0.5") || strings.Count(string(with), "\n__ARCHIVE_BELOW__\n") != 1 {
		t.Error("the rest of the header must be unchanged")
	}
}

func TestLinuxSetupArchiveFor_NamesTheAgentAfterItsArchitecture(t *testing.T) {
	archive, err := buildLinuxSetupArchiveFor("arm64", []byte("ARM-AGENT"), []byte("#!/bin/bash\n"), []byte("CA\n"))
	if err != nil {
		t.Fatal(err)
	}
	gz, _ := gzip.NewReader(bytes.NewReader(archive))
	tr := tar.NewReader(gz)
	got := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		got[h.Name] = string(b)
	}
	if got["bas-agent-linux-arm64"] != "ARM-AGENT" {
		t.Errorf("archive entries = %v", got)
	}
	if _, ok := got["bas-agent-linux-amd64"]; ok {
		t.Error("the ARM64 archive must not carry an amd64 agent")
	}
}

func TestVerifiedAgentFile_ChecksTheManifestForTheRequestedAgent(t *testing.T) {
	h := macFixture(t, "arm64", "X", sha("X")) // any agents dir with a manifest; the file name is what matters
	dir := agentArtifactDir
	if err := os.WriteFile(filepath.Join(dir, "bas-agent-linux-arm64"), []byte("L"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := h.verifiedAgentFile("bas-agent-linux-arm64"); err == nil {
		t.Error("an agent that is not listed in the signed manifest must be refused")
	}
	mf := filepath.Join(dir, "BINARIES.sha256")
	b, _ := os.ReadFile(mf)
	_ = os.WriteFile(mf, append(b, []byte(sha("L")+"  bas-agent-linux-arm64\n")...), 0o644)
	h = h.WithManifest(integrity.LoadManifest(mf))
	data, err := h.verifiedAgentFile("bas-agent-linux-arm64")
	if err != nil || string(data) != "L" {
		t.Errorf("a listed, matching agent must be returned: %v %q", err, data)
	}
}

func TestInstallScript_ChecksTheServerAndSecretBeforeTouchingTheInstalledAgent(t *testing.T) {
	s := string(installAgentLinuxScript)
	pre := strings.Index(s, "-preflight")
	un := strings.Index(s, `"$AGENT" -uninstall`)
	stale := strings.Index(s, "\nclear_stale_identity \"$TMP_CA\"")
	if pre < 0 || un < 0 || stale < 0 || !(pre < stale && pre < un) {
		t.Fatalf("the preflight must run before the old identity is moved and before the old agent is uninstalled (preflight %d, identity %d, uninstall %d)", pre, stale, un)
	}
}

// ---- behavioural run of the real install script with stand-ins ----------------------------------------------

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

const linuxFakeAgent = `#!/bin/sh
mode=other; tokfile=""
for a in "$@"; do case "$a" in -preflight|--preflight) mode=preflight;; -install|--install) mode=install;; -uninstall|--uninstall) mode=uninstall;; esac; done
while [ $# -gt 0 ]; do case "$1" in --enrollment-token-file) tokfile="$2"; shift;; esac; shift; done
secret=""; [ "$mode" = preflight ] || [ "$mode" = install ] && secret=$(cat)
printf '%s %s\n' "$mode" "$secret" >> "$AGENT_LOG"
[ "$mode" = uninstall ] && printf 'KEEP=%s\n' "$BAS_UNINSTALL_KEEP_DATA" >> "$AGENT_LOG"
if [ -n "$tokfile" ]; then printf 'TOKEN %s\n' "$(cat "$tokfile")" >> "$AGENT_LOG"; fi
[ "$mode" = preflight ] && exit "${FAKE_PREFLIGHT_EXIT:-0}"
[ "$mode" = install ] && exit "${FAKE_INSTALL_EXIT:-0}"
exit 0
`

type linuxRun struct {
	out, agentLog string
	code          int
	root          string
}

func runLinuxInstall(t *testing.T, args []string, env map[string]string, stdin string) linuxRun {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	root := t.TempDir()
	shims := filepath.Join(root, "shims")
	_ = os.MkdirAll(shims, 0o755)
	write := func(p, body string, mode os.FileMode) {
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(shims, "id"), "#!/bin/sh\necho 0\n", 0o755)
	write(filepath.Join(shims, "systemctl"), "#!/bin/sh\n[ -n \"$FAKE_SERVICE\" ] && exit 0 || exit 1\n", 0o755)
	agent := filepath.Join(root, "bas-agent-linux-amd64")
	write(agent, linuxFakeAgent, 0o755)
	ca := filepath.Join(root, "ca.pem")
	write(ca, string(testCAPEM(t)), 0o644)
	script := filepath.Join(root, "install-agent-linux.sh")
	write(script, strings.ReplaceAll(string(installAgentLinuxScript), "\r\n", "\n"), 0o755)
	logf := filepath.Join(root, "agent.log")

	argv := append([]string{filepath.ToSlash(script), "--ca-file", filepath.ToSlash(ca), "--agent", filepath.ToSlash(agent)}, args...)
	cmd := exec.Command(bash, argv...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.ToSlash(shims)+string(os.PathListSeparator)+os.Getenv("PATH"),
		"AGENT_LOG="+filepath.ToSlash(logf),
		"BAS_CERT_DIR="+filepath.ToSlash(filepath.Join(root, "certs")),
		"BAS_CA_FILE="+filepath.ToSlash(filepath.Join(root, "etc", "deployment-ca.pem")),
		"BAS_SERVER_HOST=bas.example.com", "BAS_AGENT_SECRET=LinuxSecret-4411",
	)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	r := linuxRun{out: string(out), code: code, root: root}
	if b, err := os.ReadFile(logf); err == nil {
		r.agentLog = string(b)
	}
	return r
}

func TestInstallScriptRun_ChecksTheSecretFirstThenInstalls(t *testing.T) {
	r := runLinuxInstall(t, nil, nil, "")
	if r.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.code, r.out, r.agentLog)
	}
	pre, inst := strings.Index(r.agentLog, "preflight LinuxSecret-4411"), strings.Index(r.agentLog, "install LinuxSecret-4411")
	if pre < 0 || inst < 0 || pre > inst {
		t.Errorf("the secret must be checked, then used to install, both on stdin:\n%s", r.agentLog)
	}
	if strings.Contains(r.out, "LinuxSecret-4411") {
		t.Error("the secret must never be printed")
	}
}

func TestInstallScriptRun_ARejectedSecretChangesNothingAndSaysSo(t *testing.T) {
	r := runLinuxInstall(t, nil, map[string]string{"FAKE_PREFLIGHT_EXIT": "22"}, "")
	if r.code == 0 {
		t.Error("a rejected secret must not exit 0")
	}
	if strings.Contains(r.agentLog, "install ") || strings.Contains(r.agentLog, "uninstall") {
		t.Errorf("nothing may be installed or removed when the check fails:\n%s", r.agentLog)
	}
	if !strings.Contains(strings.ToLower(r.out), "rejected the agent secret") {
		t.Errorf("the message must say the server rejected the secret:\n%s", r.out)
	}
	if _, err := os.Stat(filepath.Join(r.root, "etc", "deployment-ca.pem")); err == nil {
		t.Error("the CA must not be written when the check failed")
	}
}

func TestInstallScriptRun_AnUnreachableServerIsNotReportedAsABadSecret(t *testing.T) {
	r := runLinuxInstall(t, nil, map[string]string{"FAKE_PREFLIGHT_EXIT": "21"}, "")
	l := strings.ToLower(r.out)
	if !strings.Contains(l, "could not be reached") || strings.Contains(l, "rejected the agent secret") {
		t.Errorf("an unreachable server must be reported as such:\n%s", r.out)
	}
}

func TestInstallScriptRun_TokenModeRefusesToContinueWithoutAToken(t *testing.T) {
	r := runLinuxInstall(t, nil, map[string]string{"BAS_TOKEN_REQUIRED": "1"}, "")
	if r.code == 0 || r.agentLog != "" {
		t.Errorf("without a token nothing may run (exit %d):\n%s", r.code, r.agentLog)
	}
	if !strings.Contains(strings.ToLower(r.out), "token") {
		t.Errorf("the message must say a token is needed:\n%s", r.out)
	}
}

func TestInstallScriptRun_TokenModeInstallsWhenATokenIsGiven(t *testing.T) {
	r := runLinuxInstall(t, []string{"--token-stdin"}, map[string]string{"BAS_TOKEN_REQUIRED": "1"}, "bas_enr_LINUXTOKEN\n")
	if r.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.code, r.out, r.agentLog)
	}
	if !strings.Contains(r.agentLog, "TOKEN bas_enr_LINUXTOKEN") {
		t.Errorf("the token must reach the agent through its file:\n%s", r.agentLog)
	}
}

// Replacing an installed agent must keep its enrolment: the uninstall the installer runs is told to keep the data.
func TestInstallScriptRun_AnUpgradeKeepsTheEnrolmentWhenReplacingTheOldAgent(t *testing.T) {
	r := runLinuxInstall(t, nil, map[string]string{"FAKE_SERVICE": "1"}, "")
	if r.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.code, r.out, r.agentLog)
	}
	if !strings.Contains(r.agentLog, "KEEP=1") {
		t.Errorf("the replace step must run the uninstall with BAS_UNINSTALL_KEEP_DATA=1, or an upgrade wipes the agent's certificates:\n%s", r.agentLog)
	}
}
