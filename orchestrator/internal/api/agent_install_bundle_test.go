package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
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

func TestBuildAgentDefaultsJSON_UsesAdvertisedPorts(t *testing.T) {
	data, err := buildAgentDefaultsJSON("192.168.10.78", 9443, 9445)
	if err != nil {
		t.Fatalf("buildAgentDefaultsJSON: %v", err)
	}
	var d agentInstallDefaults
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d.ServerURL != "https://192.168.10.78:9443" {
		t.Fatalf("ServerURL = %q, want %q", d.ServerURL, "https://192.168.10.78:9443")
	}
	if d.EnrollPort != "9445" {
		t.Fatalf("EnrollPort = %q, want %q", d.EnrollPort, "9445")
	}
}

func TestBuildAgentDefaultsJSON_ZeroPorts_FallsBackToDefaults(t *testing.T) {
	data, err := buildAgentDefaultsJSON("h", 0, 0)
	if err != nil {
		t.Fatalf("buildAgentDefaultsJSON: %v", err)
	}
	var d agentInstallDefaults
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d.ServerURL != "https://h:9443" || d.EnrollPort != "9444" {
		t.Fatalf("got %+v, want default ports 9443/9444", d)
	}
}

func TestBundleInstallerZip_ContainsExecutableAndDefaults(t *testing.T) {
	execBytes := []byte("fake mach-o bytes")
	defaults := []byte(`{"serverURL":"https://h:9443"}`)

	out, err := bundleInstallerZip("BASAgent-Setup-mac", execBytes, defaults)
	if err != nil {
		t.Fatalf("bundleInstallerZip: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatalf("not a valid zip: %v", err)
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
	}

	exe, ok := files["BASAgent-Setup-mac"]
	if !ok {
		t.Fatal("missing BASAgent-Setup-mac entry")
	}
	if exe.Mode()&0111 == 0 {
		t.Fatalf("executable entry mode = %v, want executable bits set", exe.Mode())
	}
	rc, err := exe.Open()
	if err != nil {
		t.Fatalf("open exe entry: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, execBytes) {
		t.Fatal("executable entry content does not match the original bytes")
	}

	defEntry, ok := files["bas-agent-defaults.json"]
	if !ok {
		t.Fatal("missing bas-agent-defaults.json entry")
	}
	rc2, err := defEntry.Open()
	if err != nil {
		t.Fatalf("open defaults entry: %v", err)
	}
	gotDefaults, _ := io.ReadAll(rc2)
	rc2.Close()
	if !bytes.Equal(gotDefaults, defaults) {
		t.Fatal("defaults entry content does not match")
	}
}

func TestAddDefaultsToZip_PreservesExistingEntriesAndAddsDefaults(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("BASAgent-Setup.exe")
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	if _, err := w.Write([]byte("fake pe bytes")); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	original := buf.Bytes()

	defaults := []byte(`{"serverURL":"https://h:9443"}`)
	out, err := addDefaultsToZip(original, defaults)
	if err != nil {
		t.Fatalf("addDefaultsToZip: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatalf("not a valid zip: %v", err)
	}
	var sawExe, sawDefaults bool
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		switch f.Name {
		case "BASAgent-Setup.exe":
			sawExe = true
			if string(data) != "fake pe bytes" {
				t.Fatalf("exe content changed: %q", data)
			}
		case "bas-agent-defaults.json":
			sawDefaults = true
			if !bytes.Equal(data, defaults) {
				t.Fatal("defaults content mismatch")
			}
		}
	}
	if !sawExe {
		t.Fatal("original entry was lost during re-zip")
	}
	if !sawDefaults {
		t.Fatal("defaults entry was not added")
	}
}

func TestAddDefaultsToZip_RejectsInvalidZip(t *testing.T) {
	if _, err := addDefaultsToZip([]byte("not a zip"), []byte("{}")); err == nil {
		t.Fatal("expected an error for invalid zip input, got nil")
	}
}
