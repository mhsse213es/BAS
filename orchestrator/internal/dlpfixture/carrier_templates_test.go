package dlpfixture

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"image/png"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

const carrierScenarioPath = "../../../scenarios/dlp-exfiltration-file-carriers.yaml"

var (
	carrierB64Re    = regexp.MustCompile(`FromBase64String\('([A-Za-z0-9+/=]+)'\)`)
	carrierShaRe    = regexp.MustCompile(`\$sha = '([0-9a-f]{64})'`)
	carrierExpectRe = regexp.MustCompile(`\$expected = '([^']+)'`)
)

type carrierStep struct {
	format   string
	data     []byte
	sha      string
	expected string
}

func loadCarrierSteps(t *testing.T) map[string]carrierStep {
	t.Helper()
	b, err := os.ReadFile(carrierScenarioPath)
	if err != nil {
		t.Fatalf("read %s: %v", carrierScenarioPath, err)
	}
	var s scenario.Scenario
	if err := yaml.Unmarshal(b, &s); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	out := make(map[string]carrierStep)
	for _, step := range s.Steps {
		if !strings.Contains(step.Name, "Carrier Staging") {
			continue
		}
		var format string
		for _, f := range []string{"DOCX", "XLSX", "PDF", "PNG", "PPTX", "ZIP"} {
			if strings.Contains(step.Name, f) {
				format = strings.ToLower(f)
			}
		}
		m := carrierB64Re.FindStringSubmatch(step.Command)
		if m == nil {
			t.Fatalf("step %q has no embedded base64 carrier", step.Name)
		}
		data, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil {
			t.Fatalf("step %q base64 decode: %v", step.Name, err)
		}
		sha := carrierShaRe.FindStringSubmatch(step.Command)
		exp := carrierExpectRe.FindStringSubmatch(step.Command)
		if sha == nil || exp == nil {
			t.Fatalf("step %q is missing its $sha or $expected", step.Name)
		}
		out[format] = carrierStep{format: format, data: data, sha: sha[1], expected: exp[1]}
	}
	if len(out) != 6 {
		t.Fatalf("found %d carrier steps, want 6 (docx, xlsx, pdf, png, pptx, zip)", len(out))
	}
	return out
}

func TestCarrierTemplates_DecodedBytesMatchEmbeddedSHA256(t *testing.T) {
	for format, c := range loadCarrierSteps(t) {
		sum := sha256.Sum256(c.data)
		if got := hex.EncodeToString(sum[:]); got != c.sha {
			t.Errorf("%s: sha256 = %s, embedded $sha = %s", format, got, c.sha)
		}
	}
}

func TestCarrierTemplates_ParseAndContainExpectedText(t *testing.T) {
	steps := loadCarrierSteps(t)
	const want = "[BAS-SIM-DLP-CARRIER] ABCDE1234F 123456789012"

	docx := steps["docx"]
	if got := zipEntry(t, docx.data, "word/document.xml"); !strings.Contains(got, want) {
		t.Errorf("docx: word/document.xml does not contain %q", want)
	}
	xlsx := steps["xlsx"]
	if got := zipEntry(t, xlsx.data, "xl/worksheets/sheet1.xml"); !strings.Contains(got, want) {
		t.Errorf("xlsx: sheet1.xml does not contain %q", want)
	}
	pdf := steps["pdf"]
	if !bytes.HasPrefix(pdf.data, []byte("%PDF-1.4")) {
		t.Errorf("pdf: missing %%PDF header")
	}
	if !bytes.Contains(pdf.data, []byte("("+want+")")) {
		t.Errorf("pdf: text stream does not contain %q", want)
	}
	pptx := steps["pptx"]
	if got := zipEntry(t, pptx.data, "ppt/slides/slide1.xml"); !strings.Contains(got, want) {
		t.Errorf("pptx: ppt/slides/slide1.xml does not contain %q", want)
	}
	if got := zipEntry(t, pptx.data, "[Content_Types].xml"); !strings.Contains(got, "presentationml.presentation.main+xml") {
		t.Errorf("pptx: [Content_Types].xml does not declare a presentation part")
	}
	plain := steps["zip"]
	if got := zipEntry(t, plain.data, "regulated-record.txt"); !strings.Contains(got, want) {
		t.Errorf("zip: regulated-record.txt does not contain %q", want)
	}
	img, err := png.Decode(bytes.NewReader(steps["png"].data))
	if err != nil {
		t.Fatalf("png: decode: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 480 || b.Dy() != 80 {
		t.Errorf("png: bounds = %v, want 480x80", b)
	}
}

func TestCarrierTemplates_ExpectedTextIsTheRegisteredFixtureValue(t *testing.T) {
	const fixtureValue = "[BAS-SIM-DLP-CARRIER] ABCDE1234F 123456789012"
	for format, c := range loadCarrierSteps(t) {
		if c.expected != fixtureValue {
			t.Errorf("%s: $expected = %q, want the registered fixture value %q", format, c.expected, fixtureValue)
		}
	}
}

func TestCarrierTemplates_ArchiveStepStagesTheSameDOCXCarrier(t *testing.T) {
	b, err := os.ReadFile(carrierScenarioPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var s scenario.Scenario
	if err := yaml.Unmarshal(b, &s); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	docx := loadCarrierSteps(t)["docx"].data
	for _, step := range s.Steps {
		if !strings.Contains(step.Name, "Password-Protected Archive") {
			continue
		}
		m := carrierB64Re.FindStringSubmatch(step.Command)
		if m == nil {
			t.Fatal("archive step has no embedded DOCX")
		}
		got, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil {
			t.Fatalf("archive base64 decode: %v", err)
		}
		if !bytes.Equal(got, docx) {
			t.Error("archive step embeds different DOCX bytes than the DOCX carrier step")
		}
		return
	}
	t.Fatal("no password-protected archive step found")
}

func zipEntry(t *testing.T, data []byte, name string) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("zip open: %v", err)
	}
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		defer rc.Close()
		body, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(body)
	}
	t.Fatalf("zip has no entry %q", name)
	return ""
}
