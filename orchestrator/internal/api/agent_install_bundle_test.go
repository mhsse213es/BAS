package api

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequestHost_StripsPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Host = "192.168.10.78:8443"
	if got := requestHost(r); got != "192.168.10.78" {
		t.Fatalf("requestHost = %q, want %q", got, "192.168.10.78")
	}
}

func TestRequestHost_NoPort_ReturnsAsIs(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Host = "bas.example.com"
	if got := requestHost(r); got != "bas.example.com" {
		t.Fatalf("requestHost = %q, want %q", got, "bas.example.com")
	}
}

func testCARootPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "BAS Test Deployment CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestBuildAgentInstallConfigJSON_UsesAdvertisedPortsAndCARoot(t *testing.T) {
	pem := testCARootPEM(t)
	data, err := buildAgentInstallConfigJSON("192.168.10.78", 9443, 9445, pem)
	if err != nil {
		t.Fatalf("buildAgentInstallConfigJSON: %v", err)
	}
	var cfg agentInstallConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.ServerURL != "https://192.168.10.78:9443" {
		t.Errorf("ServerURL = %q", cfg.ServerURL)
	}
	if cfg.EnrollPort != "9445" {
		t.Errorf("EnrollPort = %q", cfg.EnrollPort)
	}
	if cfg.CARootPEM != pem {
		t.Errorf("CARootPEM mismatch")
	}
}

func TestBuildAgentInstallConfigJSON_ZeroPorts_FallsBackToDefaults(t *testing.T) {
	data, err := buildAgentInstallConfigJSON("h", 0, 0, "")
	if err != nil {
		t.Fatalf("buildAgentInstallConfigJSON: %v", err)
	}
	var cfg agentInstallConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.ServerURL != "https://h:9443" || cfg.EnrollPort != "9444" {
		t.Fatalf("got %+v, want default ports 9443/9444", cfg)
	}
}

// buildTestSlot constructs raw bytes shaped like a real (unpatched)
// installer binary carrying the embed slot -- same markers/size as
// installer/embedconfig.go. prefix/suffix model the surrounding binary
// content (and, realistically, the bare marker text appearing elsewhere
// in it -- see patchEmbeddedConfig's own doc comment).
func buildTestSlot(prefix, suffix string) []byte {
	fill := strings.Repeat(string(embeddedConfigFillByte), embeddedConfigSlotSize)
	return []byte(prefix + embeddedConfigBeginMarker + fill + embeddedConfigEndMarker + suffix)
}

func TestPatchEmbeddedConfig_RoundTrips(t *testing.T) {
	binary := buildTestSlot("some pe/macho header bytes ", " more trailing bytes")
	cfgJSON := []byte(`{"serverURL":"https://192.168.10.78:9443","enrollPort":"9444"}`)

	patched, err := patchEmbeddedConfig(binary, cfgJSON)
	if err != nil {
		t.Fatalf("patchEmbeddedConfig: %v", err)
	}
	if len(patched) != len(binary) {
		t.Fatalf("patched length = %d, want unchanged length %d", len(patched), len(binary))
	}

	beginIdx := strings.Index(string(patched), embeddedConfigBeginMarker) + len(embeddedConfigBeginMarker)
	endIdx := strings.Index(string(patched), embeddedConfigEndMarker)
	if endIdx-beginIdx != embeddedConfigSlotSize {
		t.Fatalf("slot size after patch = %d, want %d", endIdx-beginIdx, embeddedConfigSlotSize)
	}
	gotContent := strings.TrimRight(string(patched[beginIdx:endIdx]), string(embeddedConfigFillByte))
	if gotContent != string(cfgJSON) {
		t.Fatalf("patched content = %q, want %q", gotContent, cfgJSON)
	}
}

func TestPatchEmbeddedConfig_DoesNotMutateOriginalSlice(t *testing.T) {
	binary := buildTestSlot("", "")
	original := append([]byte(nil), binary...)
	if _, err := patchEmbeddedConfig(binary, []byte(`{"serverURL":"https://h:9443"}`)); err != nil {
		t.Fatalf("patchEmbeddedConfig: %v", err)
	}
	if !bytes.Equal(binary, original) {
		t.Fatal("patchEmbeddedConfig mutated its input slice in place")
	}
}

func TestPatchEmbeddedConfig_MissingSlot_FailsClosed(t *testing.T) {
	if _, err := patchEmbeddedConfig([]byte("no markers here at all"), []byte(`{}`)); err == nil {
		t.Fatal("expected an error when the binary has no embed slot at all")
	}
}

func TestPatchEmbeddedConfig_DuplicatedSlot_FailsClosed(t *testing.T) {
	slot := buildTestSlot("", "")
	doubled := append(append([]byte{}, slot...), slot...)
	if _, err := patchEmbeddedConfig(doubled, []byte(`{}`)); err == nil {
		t.Fatal("expected an error when the slot pattern occurs more than once")
	}
}

func TestPatchEmbeddedConfig_ConfigTooLargeForSlot_FailsClosed(t *testing.T) {
	binary := buildTestSlot("", "")
	tooBig := make([]byte, embeddedConfigSlotSize+1)
	for i := range tooBig {
		tooBig[i] = 'a'
	}
	if _, err := patchEmbeddedConfig(binary, tooBig); err == nil {
		t.Fatal("expected an error when the config does not fit in the slot")
	}
}

func TestPatchEmbeddedConfig_BareMarkerElsewhereDoesNotConfuseRealSlot(t *testing.T) {
	binary := buildTestSlot("prefix with a bare "+embeddedConfigBeginMarker+" sitting unrelated here ", "")
	patched, err := patchEmbeddedConfig(binary, []byte(`{"serverURL":"https://h:9443"}`))
	if err != nil {
		t.Fatalf("a bare, unrelated marker occurrence must not fail the real slot: %v", err)
	}
	if len(patched) != len(binary) {
		t.Fatalf("patched length changed: %d vs %d", len(patched), len(binary))
	}
}

// buildTestZip wraps binary (the installer executable's content) as the
// single entry of a zip, matching the shape of the real pre-built
// bas-agent-windows-amd64-setup.zip.
func buildTestZip(t *testing.T, entryName string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(entryName)
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func TestPatchEmbeddedConfigInZip_RoundTrips(t *testing.T) {
	exe := buildTestSlot("MZ fake PE header ", "")
	zipBytes := buildTestZip(t, "Audspect_Agent.exe", exe)
	cfgJSON := []byte(`{"serverURL":"https://192.168.10.78:9443","enrollPort":"9444"}`)

	patchedZip, err := patchEmbeddedConfigInZip(zipBytes, cfgJSON)
	if err != nil {
		t.Fatalf("patchEmbeddedConfigInZip: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(patchedZip), int64(len(patchedZip)))
	if err != nil {
		t.Fatalf("patched zip is not a valid zip: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("patched zip has %d entries, want 1", len(zr.File))
	}
	if zr.File[0].Name != "Audspect_Agent.exe" {
		t.Fatalf("entry name = %q, want Audspect_Agent.exe", zr.File[0].Name)
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("open patched entry: %v", err)
	}
	patchedExe, _ := io.ReadAll(rc)
	rc.Close()
	if len(patchedExe) != len(exe) {
		t.Fatalf("patched entry length = %d, want unchanged %d", len(patchedExe), len(exe))
	}
	if !bytes.Contains(patchedExe, cfgJSON) {
		t.Fatal("patched entry does not contain the config JSON")
	}
}

func TestPatchEmbeddedConfigInZip_InvalidZip_FailsClosed(t *testing.T) {
	if _, err := patchEmbeddedConfigInZip([]byte("not a zip"), []byte(`{}`)); err == nil {
		t.Fatal("expected an error for invalid zip input")
	}
}

func TestPatchEmbeddedConfigInZip_MultipleEntries_FailsClosed(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w1, _ := zw.Create("a.exe")
	w1.Write([]byte("a"))
	w2, _ := zw.Create("b.exe")
	w2.Write([]byte("b"))
	zw.Close()

	if _, err := patchEmbeddedConfigInZip(buf.Bytes(), []byte(`{}`)); err == nil {
		t.Fatal("expected an error for a zip with more than one entry")
	}
}

func TestPatchEmbeddedConfigInZip_EntryMissingSlot_FailsClosed(t *testing.T) {
	zipBytes := buildTestZip(t, "Audspect_Agent.exe", []byte("no markers in here"))
	if _, err := patchEmbeddedConfigInZip(zipBytes, []byte(`{}`)); err == nil {
		t.Fatal("expected an error when the zip entry has no embed slot")
	}
}
