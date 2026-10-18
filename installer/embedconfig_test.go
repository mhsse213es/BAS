package main

import (
	"strings"
	"testing"
)

func TestEmbeddedConfigSlot_HasExactlyOneBeginAndEndMarker(t *testing.T) {
	if n := strings.Count(embeddedConfigSlot, embeddedConfigBeginMarker); n != 1 {
		t.Fatalf("begin marker occurs %d times, want exactly 1", n)
	}
	if n := strings.Count(embeddedConfigSlot, embeddedConfigEndMarker); n != 1 {
		t.Fatalf("end marker occurs %d times, want exactly 1", n)
	}
}

func TestEmbeddedConfigSlot_GapIsExactlySlotSize(t *testing.T) {
	beginIdx := strings.Index(embeddedConfigSlot, embeddedConfigBeginMarker) + len(embeddedConfigBeginMarker)
	endIdx := strings.Index(embeddedConfigSlot, embeddedConfigEndMarker)
	if endIdx-beginIdx != embeddedConfigSlotSize {
		t.Fatalf("gap = %d bytes, want %d", endIdx-beginIdx, embeddedConfigSlotSize)
	}
}

func TestExtractEmbeddedConfig_UnpatchedSlot_ReturnsBenignZeroValue(t *testing.T) {
	cfg, err := extractEmbeddedConfig([]byte(embeddedConfigSlot))
	if err != nil {
		t.Fatalf("unpatched slot must not be an error, got: %v", err)
	}
	if cfg.ServerURL != "" || cfg.EnrollPort != "" || cfg.CARootPEM != "" {
		t.Fatalf("expected zero value for an unpatched slot, got %+v", cfg)
	}
}

func TestExtractEmbeddedConfig_MissingMarkers_IsBenign(t *testing.T) {
	// A binary that was never built with this mechanism at all (e.g. an
	// older release) must not be treated as tampered -- there is simply
	// nothing to extract.
	cfg, err := extractEmbeddedConfig([]byte("just some random binary data, no markers at all"))
	if err != nil {
		t.Fatalf("missing markers entirely must be benign, got error: %v", err)
	}
	if cfg != (embeddedConfig{}) {
		t.Fatalf("expected zero value, got %+v", cfg)
	}
}

func TestExtractEmbeddedConfig_DuplicatedFullSlotPattern_FailsClosed(t *testing.T) {
	// Two complete, individually well-formed slot patterns back to back --
	// the bare marker text appearing elsewhere in a normal binary (see
	// extractEmbeddedConfig's own doc comment) must NOT trip this check,
	// only a second genuinely full-size match does.
	tampered := embeddedConfigSlot + embeddedConfigSlot
	if _, err := extractEmbeddedConfig([]byte(tampered)); err == nil {
		t.Fatal("expected an error when the full slot pattern appears more than once")
	}
}

func TestExtractEmbeddedConfig_BareMarkerElsewhereInBinary_DoesNotConfuseRealSlot(t *testing.T) {
	// Models what a real compiled binary actually looks like: the bare
	// marker text appears a second time (e.g. passed as a plain argument
	// to strings.Index inside this very function), unrelated to and not
	// immediately followed by a correctly sized gap + end marker. That
	// must not be mistaken for a second slot, and must not stop the one
	// real, valid slot from being extracted.
	pem := validTestCARootPEM(t)
	validSlot := validPatchedSlot(t, "https://192.168.10.78:9443", "9444", pem)
	withBareMarkerElsewhere := append([]byte("prefix "+embeddedConfigBeginMarker+" unrelated bytes, no end marker nearby "), validSlot...)
	cfg, err := extractEmbeddedConfig(withBareMarkerElsewhere)
	if err != nil {
		t.Fatalf("a bare, unrelated marker occurrence must not fail the real slot: %v", err)
	}
	if cfg.ServerURL != "https://192.168.10.78:9443" {
		t.Fatalf("ServerURL = %q", cfg.ServerURL)
	}
}

func TestExtractEmbeddedConfig_WrongGapSize_FailsClosed(t *testing.T) {
	tampered := embeddedConfigBeginMarker + strings.Repeat("~", embeddedConfigSlotSize-1) + embeddedConfigEndMarker
	if _, err := extractEmbeddedConfig([]byte(tampered)); err == nil {
		t.Fatal("expected an error when the gap between markers is the wrong size")
	}
}

func validPatchedSlot(t *testing.T, serverURL, enrollPort, caRootPEM string) []byte {
	t.Helper()
	cfg := embeddedConfig{ServerURL: serverURL, EnrollPort: enrollPort, CARootPEM: caRootPEM}
	data := mustMarshalEmbeddedConfig(t, cfg)
	if len(data) > embeddedConfigSlotSize {
		t.Fatalf("fixture config too large: %d > %d", len(data), embeddedConfigSlotSize)
	}
	padded := string(data) + strings.Repeat("~", embeddedConfigSlotSize-len(data))
	return []byte(embeddedConfigBeginMarker + padded + embeddedConfigEndMarker)
}

func TestExtractEmbeddedConfig_ValidPatch_RoundTrips(t *testing.T) {
	pem := validTestCARootPEM(t)
	slot := validPatchedSlot(t, "https://192.168.10.78:9443", "9444", pem)
	cfg, err := extractEmbeddedConfig(slot)
	if err != nil {
		t.Fatalf("extractEmbeddedConfig: %v", err)
	}
	if cfg.ServerURL != "https://192.168.10.78:9443" {
		t.Errorf("ServerURL = %q", cfg.ServerURL)
	}
	if cfg.EnrollPort != "9444" {
		t.Errorf("EnrollPort = %q", cfg.EnrollPort)
	}
	if cfg.CARootPEM != pem {
		t.Errorf("CARootPEM mismatch")
	}
}

func TestExtractEmbeddedConfig_MalformedJSON_FailsClosed(t *testing.T) {
	padded := `{"serverURL":` + strings.Repeat("~", embeddedConfigSlotSize-14)
	slot := []byte(embeddedConfigBeginMarker + padded + embeddedConfigEndMarker)
	if _, err := extractEmbeddedConfig(slot); err == nil {
		t.Fatal("expected an error for malformed JSON content")
	}
}

func TestExtractEmbeddedConfig_NonHTTPSScheme_FailsClosed(t *testing.T) {
	slot := validPatchedSlot(t, "http://192.168.10.78:9443", "9444", "")
	if _, err := extractEmbeddedConfig(slot); err == nil {
		t.Fatal("expected an error for a non-https server URL scheme")
	}
}

func TestExtractEmbeddedConfig_MalformedURL_FailsClosed(t *testing.T) {
	slot := validPatchedSlot(t, "https://[::1", "9444", "")
	if _, err := extractEmbeddedConfig(slot); err == nil {
		t.Fatal("expected an error for a malformed server URL")
	}
}

func TestExtractEmbeddedConfig_EmptyHost_FailsClosed(t *testing.T) {
	slot := validPatchedSlot(t, "https:///path-only-no-host", "9444", "")
	if _, err := extractEmbeddedConfig(slot); err == nil {
		t.Fatal("expected an error for a server URL with no host")
	}
}

func TestExtractEmbeddedConfig_InvalidEnrollPort_FailsClosed(t *testing.T) {
	for _, port := range []string{"0", "65536", "not-a-number", "-1"} {
		slot := validPatchedSlot(t, "https://h:9443", port, "")
		if _, err := extractEmbeddedConfig(slot); err == nil {
			t.Errorf("port %q: expected an error", port)
		}
	}
}

func TestExtractEmbeddedConfig_EnrollPortOmitted_IsAllowed(t *testing.T) {
	slot := validPatchedSlot(t, "https://h:9443", "", "")
	cfg, err := extractEmbeddedConfig(slot)
	if err != nil {
		t.Fatalf("an omitted enroll port must be allowed, got: %v", err)
	}
	if cfg.EnrollPort != "" {
		t.Errorf("EnrollPort = %q, want empty", cfg.EnrollPort)
	}
}

func TestExtractEmbeddedConfig_MalformedCAPEM_FailsClosed(t *testing.T) {
	slot := validPatchedSlot(t, "https://h:9443", "9444", "not a pem certificate at all")
	if _, err := extractEmbeddedConfig(slot); err == nil {
		t.Fatal("expected an error for a malformed CA PEM")
	}
}

func TestExtractEmbeddedConfig_NonCertificatePEMBlock_FailsClosed(t *testing.T) {
	// A well-formed PEM block that isn't a CERTIFICATE (e.g. a private key
	// label) must never be accepted as a trust anchor.
	fakeKeyPEM := "-----BEGIN RSA PRIVATE KEY-----\nMAA=\n-----END RSA PRIVATE KEY-----\n"
	slot := validPatchedSlot(t, "https://h:9443", "9444", fakeKeyPEM)
	if _, err := extractEmbeddedConfig(slot); err == nil {
		t.Fatal("expected an error for a non-CERTIFICATE PEM block")
	}
}

func TestExtractEmbeddedConfig_CAPEMNotStructurallyValidCert_FailsClosed(t *testing.T) {
	// Correct PEM armor, but the base64 payload does not decode as a real
	// X.509 certificate.
	bogus := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	slot := validPatchedSlot(t, "https://h:9443", "9444", bogus)
	if _, err := extractEmbeddedConfig(slot); err == nil {
		t.Fatal("expected an error for a PEM block that is not a valid X.509 certificate")
	}
}

func TestExtractEmbeddedConfig_CAPEMOmitted_IsAllowed(t *testing.T) {
	slot := validPatchedSlot(t, "https://h:9443", "9444", "")
	cfg, err := extractEmbeddedConfig(slot)
	if err != nil {
		t.Fatalf("an omitted CA root must be allowed (benign -- PKI not configured server-side), got: %v", err)
	}
	if cfg.CARootPEM != "" {
		t.Errorf("CARootPEM = %q, want empty", cfg.CARootPEM)
	}
}
