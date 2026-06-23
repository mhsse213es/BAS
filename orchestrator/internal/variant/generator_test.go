package variant

import (
	"encoding/base64"
	"strings"
	"testing"
)

const psScript = "whoami"

func TestGenerateReturnsNilForNonPSExecutor(t *testing.T) {
	if got := Generate("T1059.001", "art", "test", psScript, "bash", false); got != nil {
		t.Errorf("expected nil for bash executor, got %d templates", len(got))
	}
}

func TestGenerateReturnsNilForEmptyScript(t *testing.T) {
	if got := Generate("T1059.001", "art", "test", "", "powershell", false); got != nil {
		t.Errorf("expected nil for empty script, got %d templates", len(got))
	}
}

func TestGenerateDefaultCount(t *testing.T) {
	// 4 enc × 4 ctx × 4 evasions = 64
	// minus gzip_b64 + wmi  (4 evasions) = -4
	// minus gzip_b64 + schedtask (4 evasions) = -4
	// = 56 default variants
	const want = 56
	got := Generate("T1059.001", "art", "test", psScript, "powershell", false)
	if len(got) != want {
		t.Errorf("Generate (default) count = %d, want %d", len(got), want)
	}
}

func TestGenerateAdvancedCount(t *testing.T) {
	// 4 enc × 4 ctx × 5 evasions = 80
	// minus gzip_b64 + wmi  (5) = -5
	// minus gzip_b64 + schedtask (5) = -5
	// = 70 advanced variants
	const want = 70
	got := Generate("T1059.001", "art", "test", psScript, "powershell", true)
	if len(got) != want {
		t.Errorf("Generate (advanced) count = %d, want %d", len(got), want)
	}
}

func TestVariantsPerFamily(t *testing.T) {
	if got := VariantsPerFamily(false); got != 56 {
		t.Errorf("VariantsPerFamily(false) = %d, want 56", got)
	}
	if got := VariantsPerFamily(true); got != 70 {
		t.Errorf("VariantsPerFamily(true) = %d, want 70", got)
	}
}

func TestBase64EncodingIsUTF16LE(t *testing.T) {
	b64str, err := encodePS(psScript, EncBase64)
	if err != nil {
		t.Fatalf("encodePS error: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(b64str)
	if err != nil {
		t.Fatalf("base64 decode error: %v", err)
	}
	if len(raw)%2 != 0 {
		t.Fatalf("UTF-16LE byte length must be even, got %d", len(raw))
	}
	for i := 1; i < len(raw); i += 2 {
		if raw[i] != 0x00 {
			t.Errorf("UTF-16LE high byte at index %d = 0x%02x, want 0x00", i, raw[i])
		}
	}
	reconstructed := make([]byte, len(raw)/2)
	for i := range reconstructed {
		reconstructed[i] = raw[i*2]
	}
	if string(reconstructed) != psScript {
		t.Errorf("decoded UTF-16LE = %q, want %q", reconstructed, psScript)
	}
}

func TestGzipB64SkipsWMIAndSchedTask(t *testing.T) {
	templates := Generate("T1059.001", "art", "test", psScript, "powershell", true)
	for _, tmpl := range templates {
		if tmpl.Encoding == EncGzipB64 {
			if tmpl.ExecContext == CtxWMI || tmpl.ExecContext == CtxSchedTask {
				t.Errorf("gzip_b64 must not produce WMI/schedtask variant, got: %+v", tmpl)
			}
		}
	}
}

func TestCharCodeIexForm(t *testing.T) {
	for _, tmpl := range Generate("T1059.001", "art", "test", psScript, "powershell", false) {
		if tmpl.Encoding == EncCharCode && tmpl.ExecContext == CtxPowershellDirect {
			if !strings.HasPrefix(tmpl.Command, "iex([char[]](") {
				t.Errorf("charcode/powershell_direct should start with iex([char[]](, got: %.60s", tmpl.Command)
			}
			break
		}
	}
}

func TestTemplateIDIsStable(t *testing.T) {
	id1 := TemplateID("T1059.001", "Invoke-Expression", EncBase64, CtxWMI, EvasionNone)
	id2 := TemplateID("T1059.001", "Invoke-Expression", EncBase64, CtxWMI, EvasionNone)
	if id1 != id2 {
		t.Errorf("TemplateID not stable: %s != %s", id1, id2)
	}
}

func TestVariantHashIsStableAndLen16(t *testing.T) {
	tid := TemplateID("T1059.001", "test", EncBase64, CtxWMI, EvasionNone)
	h1, h2 := variantHash(tid), variantHash(tid)
	if h1 != h2 {
		t.Errorf("variantHash not stable: %s != %s", h1, h2)
	}
	if len(h1) != 16 {
		t.Errorf("variantHash length = %d, want 16", len(h1))
	}
}

func TestEvasionSleepJitter(t *testing.T) {
	r := applyEvasion(psScript, EvasionSleepJitter)
	if !strings.Contains(r, "Start-Sleep") || !strings.Contains(r, "Get-Random") {
		t.Errorf("sleep_jitter missing Start-Sleep/Get-Random: %s", r)
	}
}

func TestEvasionDelay(t *testing.T) {
	r := applyEvasion(psScript, EvasionDelay)
	if !strings.HasPrefix(r, "Start-Sleep -Seconds 5") {
		t.Errorf("delay should start with fixed 5s sleep, got: %s", r)
	}
	if !strings.HasSuffix(r, psScript) {
		t.Errorf("delay should end with original script")
	}
}

func TestEvasionParentShiftContainsStartProcess(t *testing.T) {
	r := applyEvasion(psScript, EvasionParentShift)
	if !strings.HasPrefix(r, "Start-Process powershell.exe") {
		t.Errorf("parent_process_shift should start with Start-Process, got: %.80s", r)
	}
	if !strings.Contains(r, "-EncodedCommand") {
		t.Errorf("parent_process_shift should embed inner script as -EncodedCommand")
	}
	// Inner command should be valid UTF-16LE base64 of the original script.
	parts := strings.Fields(r)
	for i, p := range parts {
		if p == "-EncodedCommand" && i+1 < len(parts) {
			// Trim trailing quote if present.
			blob := strings.TrimRight(parts[i+1], "'")
			raw, err := base64.StdEncoding.DecodeString(blob)
			if err != nil {
				t.Errorf("inner b64 decode error: %v", err)
				break
			}
			// UTF-16LE: odd bytes are 0x00 for ASCII
			for j := 1; j < len(raw); j += 2 {
				if raw[j] != 0x00 {
					t.Errorf("inner UTF-16LE high byte[%d] = 0x%02x, want 0x00", j, raw[j])
				}
			}
			break
		}
	}
}

func TestEvasionAMSIPatch(t *testing.T) {
	r := applyEvasion(psScript, EvasionAMSIPatch)
	if !strings.Contains(r, "amsiInitFailed") {
		t.Errorf("amsi_patch missing amsiInitFailed: %s", r)
	}
}

func TestAMSIPatchNotInDefaultRun(t *testing.T) {
	templates := Generate("T1059.001", "art", "test", psScript, "powershell", false)
	for _, tmpl := range templates {
		if tmpl.Evasion == EvasionAMSIPatch {
			t.Errorf("amsi_patch must not appear in default (non-advanced) run")
		}
	}
}

func TestAMSIPatchAppearsInAdvancedRun(t *testing.T) {
	found := false
	for _, tmpl := range Generate("T1059.001", "art", "test", psScript, "powershell", true) {
		if tmpl.Evasion == EvasionAMSIPatch {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("amsi_patch should appear when includeAdvanced=true")
	}
}

func TestRiskLevelAssignment(t *testing.T) {
	cases := []struct {
		enc, ev   string
		wantRisk  RiskLevel
	}{
		{EncPlain, EvasionNone, RiskSafe},
		{EncPlain, EvasionDelay, RiskSafe},
		{EncPlain, EvasionSleepJitter, RiskSafe},
		{EncBase64, EvasionNone, RiskModerate},
		{EncGzipB64, EvasionNone, RiskModerate},
		{EncCharCode, EvasionNone, RiskModerate},
		{EncPlain, EvasionParentShift, RiskModerate},
		{EncBase64, EvasionParentShift, RiskModerate},
		{EncPlain, EvasionAMSIPatch, RiskAdvanced},
		{EncBase64, EvasionAMSIPatch, RiskAdvanced},
	}
	for _, c := range cases {
		got := assignRiskLevel(c.enc, c.ev)
		if got != c.wantRisk {
			t.Errorf("assignRiskLevel(%q, %q) = %q, want %q", c.enc, c.ev, got, c.wantRisk)
		}
	}
}

func TestGenerateFromFamiliesDeduplicates(t *testing.T) {
	// Two families with identical payload → same variant hashes → deduplication
	families := []PayloadFamily{
		{Name: "a", Payload: psScript, Executor: "powershell"},
		{Name: "b", Payload: psScript, Executor: "powershell"},
	}
	got := GenerateFromFamilies("T1059.001", "art", families, false)
	single := Generate("T1059.001", "art", "a", psScript, "powershell", false)
	// Different baseIDs mean different TemplateIDs and different hashes — no dedup.
	// The dedup only fires when two families produce the SAME hash (same content+dims).
	// Since baseID differs ("a" vs "b"), TemplateID differs, hash differs — no dedup here.
	// Total should be 2 × 56 = 112.
	if len(got) != 2*len(single) {
		t.Errorf("GenerateFromFamilies 2×same payload = %d, want %d", len(got), 2*len(single))
	}
}

func TestScheduledTaskNameIsDeterministic(t *testing.T) {
	h1 := variantShortHash("T1059.001", "test", EncBase64)
	h2 := variantShortHash("T1059.001", "test", EncBase64)
	if h1 != h2 {
		t.Errorf("variantShortHash not deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 6 {
		t.Errorf("variantShortHash length = %d, want 6", len(h1))
	}
}
