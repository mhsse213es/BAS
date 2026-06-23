package variant

import (
	"encoding/base64"
	"strings"
	"testing"
)

const psScript = "whoami"

func TestGenerateReturnsNilForNonPSExecutor(t *testing.T) {
	if got := Generate("T1059.001", "art", "test", psScript, "bash"); got != nil {
		t.Errorf("expected nil for bash executor, got %d templates", len(got))
	}
}

func TestGenerateReturnsNilForEmptyScript(t *testing.T) {
	if got := Generate("T1059.001", "art", "test", "", "powershell"); got != nil {
		t.Errorf("expected nil for empty script, got %d templates", len(got))
	}
}

func TestGenerateTotalCount(t *testing.T) {
	// 4 encodings × 4 contexts × 3 evasions = 48 max
	// minus gzip_b64 + WMI (3 evasions) = -3
	// minus gzip_b64 + schedtask (3 evasions) = -3
	// = 42 valid combinations
	const want = 42
	got := Generate("T1059.001", "art", "test", psScript, "powershell")
	if len(got) != want {
		t.Errorf("Generate count = %d, want %d", len(got), want)
	}
}

func TestBase64EncodingIsUTF16LE(t *testing.T) {
	// Plain script with no evasion produces base64 whose decoded form is UTF-16LE.
	// ASCII UTF-16LE: every odd byte (high byte of pair) must be 0x00.
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
	// Verify the low bytes spell the script.
	reconstructed := make([]byte, len(raw)/2)
	for i := range reconstructed {
		reconstructed[i] = raw[i*2]
	}
	if string(reconstructed) != psScript {
		t.Errorf("decoded UTF-16LE = %q, want %q", reconstructed, psScript)
	}
}

func TestGzipB64SkipsWMIAndSchedTask(t *testing.T) {
	templates := Generate("T1059.001", "art", "test", psScript, "powershell")
	for _, tmpl := range templates {
		if tmpl.Encoding == EncGzipB64 {
			if tmpl.ExecContext == CtxWMI || tmpl.ExecContext == CtxSchedTask {
				t.Errorf("gzip_b64 should not generate WMI or schedtask variants, got: %+v", tmpl)
			}
		}
	}
}

func TestCharCodeIexForm(t *testing.T) {
	templates := Generate("T1059.001", "art", "test", psScript, "powershell")
	for _, tmpl := range templates {
		if tmpl.Encoding != EncCharCode {
			continue
		}
		// powershell_direct charcode: executor=powershell, command starts with iex
		if tmpl.ExecContext == CtxPowershellDirect {
			if !strings.HasPrefix(tmpl.Command, "iex([char[]](") {
				t.Errorf("charcode/powershell_direct command should start with iex([char[]], got: %.60s", tmpl.Command)
			}
		}
		break
	}
}

func TestTemplateIDIsStable(t *testing.T) {
	id1 := TemplateID("T1059.001", "Invoke-Expression", EncBase64, CtxWMI, EvasionNone)
	id2 := TemplateID("T1059.001", "Invoke-Expression", EncBase64, CtxWMI, EvasionNone)
	if id1 != id2 {
		t.Errorf("TemplateID not stable: %s != %s", id1, id2)
	}
}

func TestEvasionAMSIPatch(t *testing.T) {
	result := applyEvasion(psScript, EvasionAMSIPatch)
	if !strings.Contains(result, "amsiInitFailed") {
		t.Errorf("AMSI patch evasion missing amsiInitFailed: %s", result)
	}
	if !strings.HasSuffix(result, psScript) {
		t.Errorf("AMSI patch should end with original script")
	}
}

func TestEvasionSleepJitter(t *testing.T) {
	result := applyEvasion(psScript, EvasionSleepJitter)
	if !strings.Contains(result, "Start-Sleep") {
		t.Errorf("sleep jitter missing Start-Sleep: %s", result)
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
