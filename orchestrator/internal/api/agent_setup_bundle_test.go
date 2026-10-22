package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildLinuxSetupScript_EmbedsServerDetails(t *testing.T) {
	script, err := buildLinuxSetupScript("192.168.10.78", 9445, 9443, 9543)
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	if !strings.HasPrefix(s, "#!/bin/sh\n") {
		t.Fatal("setup file must start with a shell shebang")
	}
	for _, want := range []string{
		"BAS_SERVER_HOST=192.168.10.78", "BAS_ENROLL_PORT=9445", "BAS_MTLS_PORT=9443", "BAS_DASHBOARD_PORT=9543",
		"bash install-agent-linux.sh --ca-file ./deployment-ca.pem --agent ./bas-agent-linux-amd64",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("setup script missing %q", want)
		}
	}
	if n := strings.Count(s, "\n__ARCHIVE_BELOW__\n"); n != 1 {
		t.Fatalf("archive marker must appear exactly once on its own line, got %d", n)
	}
}

func TestBuildLinuxSetupScript_RejectsUnsafeHost(t *testing.T) {
	for _, host := range []string{"a;rm -rf /", "$(id)", "a b", "-", "", "host`x`", "[::1]"} {
		if _, err := buildLinuxSetupScript(host, 9445, 9443, 9543); err == nil {
			t.Fatalf("host %q must be refused", host)
		}
	}
}

func TestBuildLinuxSetupScript_RejectsBadPort(t *testing.T) {
	if _, err := buildLinuxSetupScript("10.0.0.5", 0, 9443, 9543); err == nil {
		t.Fatal("port 0 must be refused")
	}
	if _, err := buildLinuxSetupScript("10.0.0.5", 9445, 70000, 9543); err == nil {
		t.Fatal("port above 65535 must be refused")
	}
}

func TestLinuxSetupArchive_ContainsInstallerAgentAndCA(t *testing.T) {
	agent := []byte("AGENT-BYTES")
	script := []byte("#!/bin/bash\necho install\n")
	ca := []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n")
	archive, err := buildLinuxSetupArchive(agent, script, ca)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	got := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		got[hdr.Name] = string(b)
	}
	want := map[string]string{
		"install-agent-linux.sh": string(script),
		"bas-agent-linux-amd64":  string(agent),
		"deployment-ca.pem":      string(ca),
	}
	for name, content := range want {
		if got[name] != content {
			t.Fatalf("%s: got %q, want %q", name, got[name], content)
		}
	}
}

// The setup file must unpack with the same steps its header uses (awk to find the archive, tail to
// cut it, tar to extract). Skipped when bash is not installed.
func TestLinuxSetupRun_HeaderExtractsPayload(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	script, err := buildLinuxSetupScript("10.0.0.5", 9445, 9443, 9543)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := buildLinuxSetupArchive([]byte("AGENT"), []byte("#!/bin/bash\n"), []byte("CA\n"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	run := filepath.Join(dir, "setup.run")
	if err := os.WriteFile(run, append(script, archive...), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, "-c",
		`OFFSET=$(awk '/^__ARCHIVE_BELOW__$/ { print NR + 1; exit 0 }' "$0"); tail -n +"$OFFSET" "$0" | tar -xz -C "$1"`,
		filepath.ToSlash(run), filepath.ToSlash(out))
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("extraction failed: %v\n%s", err, b)
	}
	for name, want := range map[string]string{"bas-agent-linux-amd64": "AGENT", "deployment-ca.pem": "CA\n"} {
		b, err := os.ReadFile(filepath.Join(out, name))
		if err != nil || string(b) != want {
			t.Fatalf("%s: err=%v got %q, want %q", name, err, b, want)
		}
	}
}

// Without a deployment CA the setup file would have no trust anchor, so the server must refuse to build it.
func TestServeLinuxSetup_RefusesWithoutDeploymentCA(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "/api/agents/download/linux-amd64-setup", nil)
	rec := httptest.NewRecorder()
	h.serveLinuxSetup(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
	if rec.Body.Len() > 0 && strings.Contains(rec.Body.String(), "#!/bin/sh") {
		t.Fatal("a setup file was returned without a CA")
	}
}
