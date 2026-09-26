package reporting

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/models"
)

func TestBuildNavigatorLayer(t *testing.T) {
	rep := &FullReport{
		Agent: models.Agent{Hostname: "WIN-PROD-01"},
		TechniqueMatrix: []TechniqueRow{
			{TechniqueID: "T1003.001", ExecVerdict: "fail", DetectionVerdict: "undetected"},
			{TechniqueID: "T1059.001", ExecVerdict: "pass", DetectionVerdict: "prevented"},
			{TechniqueID: "T1071", ExecVerdict: "fail", DetectionVerdict: "detected"},
		},
	}
	layer := BuildNavigatorLayer(rep, "Test Layer")
	if layer.Domain != "enterprise-attack" || layer.Versions.Layer != "4.5" {
		t.Errorf("unexpected layer meta: %+v", layer.Versions)
	}
	// Sub-techniques collapse to their base for coloring.
	got := map[string]NavigatorTech{}
	for _, tq := range layer.Techniques {
		got[tq.TechniqueID] = tq
	}
	if _, ok := got["T1003"]; !ok {
		t.Error("expected base technique T1003 from T1003.001")
	}
	if got["T1003"].Color != navMissedColor {
		t.Errorf("undetected fail should be missed(red), got %s", got["T1003"].Color)
	}
	if got["T1059"].Color != navPreventedColor {
		t.Errorf("prevented should be teal, got %s", got["T1059"].Color)
	}
	if got["T1071"].Color != navDetectedColor {
		t.Errorf("detected-only should be blue, got %s", got["T1071"].Color)
	}
	if len(layer.LegendItems) != 4 {
		t.Errorf("expected 4 legend items, got %d", len(layer.LegendItems))
	}
}

func TestNavigatorWorstOutcomeWins(t *testing.T) {
	// Same base technique, one prevented atomic and one missed atomic → missed.
	rep := &FullReport{TechniqueMatrix: []TechniqueRow{
		{TechniqueID: "T1003.001", ExecVerdict: "pass", DetectionVerdict: "prevented"},
		{TechniqueID: "T1003.002", ExecVerdict: "fail", DetectionVerdict: "undetected"},
	}}
	layer := BuildNavigatorLayer(rep, "")
	if len(layer.Techniques) != 1 {
		t.Fatalf("expected 1 collapsed technique, got %d", len(layer.Techniques))
	}
	if layer.Techniques[0].Color != navMissedColor {
		t.Errorf("worst outcome should win (missed), got %s", layer.Techniques[0].Color)
	}
}

// TestManifestRoundTrip covers the full P0-2 verify path: build → sign → parse →
// verify, plus tamper detection.
func TestManifestRoundTrip(t *testing.T) {
	SetSigningSecret("verify-round-trip-deployment-secret-key!!")
	t.Cleanup(func() { SetSigningSecret("") })

	hashA := strings.Repeat("a", 64)
	hashC := strings.Repeat("c", 64)
	entries := []ManifestEntry{
		{Path: "a.txt", SHA256: hashA},
		{Path: "b/c.json", SHA256: hashC},
	}
	manifest := BuildManifest(entries)

	parsed := ParseManifest(manifest)
	if len(parsed) != 2 || parsed[0].Path != "a.txt" || parsed[0].SHA256 != hashA {
		t.Fatalf("parse round-trip failed: %+v", parsed)
	}

	att := Attest(manifest, "user-1")
	digestMatch, sigValid := VerifyManifestSignature(manifest, att)
	if !digestMatch || !sigValid {
		t.Fatalf("verify failed on untampered manifest: digest=%v sig=%v", digestMatch, sigValid)
	}

	// Tamper the manifest → digest no longer matches the attestation.
	tampered := append([]byte{}, manifest...)
	tampered = append(tampered, []byte("ddd  evil.sh\n")...)
	if dm, _ := VerifyManifestSignature(tampered, att); dm {
		t.Error("tampered manifest should not match the attestation digest")
	}
}
