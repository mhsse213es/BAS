package iocregistry

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
)

const credentialCommandLine = "mimikatz.exe sekurlsa::pth /user:Administrator /ntlm:aad3b435b51404eeaad3b435b51404ee"

func credentialDetectionResult(tactic string, commandLine string) models.SimulationResult {
	res := detectionResult(commandLine, "mimikatz.exe", "")
	res.Technique = models.AttackTechnique{ID: "T1003.001", Tactic: tactic}
	return res
}

// A command line from a credential-access step can carry the credential it
// used (here an NTLM hash passed to pass-the-hash). The registry is served
// cross-run to every viewer, so that hash must not be stored, while the
// command line itself still is, so the sighting is kept.
func TestExtractFromDetectionAlert_CredentialAccessCommandLineWithheld(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		res := credentialDetectionResult("credential-access", credentialCommandLine)
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", "T1003.001", "detected", res); err != nil {
			t.Fatalf("ExtractFromDetectionAlert: %v", err)
		}
		rows, err := pool.Query(context.Background(), `SELECT value FROM iocs WHERE type = 'command_line'`)
		if err != nil {
			t.Fatalf("query command_line rows: %v", err)
		}
		defer rows.Close()
		var values []string
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				t.Fatalf("scan: %v", err)
			}
			values = append(values, v)
		}
		if len(values) != 1 {
			t.Fatalf("command_line rows = %d, want 1 (sighting must be kept)", len(values))
		}
		if strings.Contains(values[0], "aad3b435b51404eeaad3b435b51404ee") {
			t.Fatalf("credential hash stored in registry: %q", values[0])
		}
		if !strings.Contains(values[0], "sekurlsa::pth") {
			t.Fatalf("command line lost its non-credential content: %q", values[0])
		}
	})
}

// Command lines from non-credential techniques are stored verbatim.
func TestExtractFromDetectionAlert_OtherCommandLineUnchanged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		const cmd = "certutil -hashfile payload.exe b1946ac92492d2347c6235b4d2611184"
		res := credentialDetectionResult("execution", cmd)
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", "T1059", "detected", res); err != nil {
			t.Fatalf("ExtractFromDetectionAlert: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM iocs WHERE type = 'command_line' AND value = $1`, cmd).Scan(&count); err != nil {
			t.Fatalf("query: %v", err)
		}
		if count != 1 {
			t.Fatalf("non-credential command line stored %d times verbatim, want 1", count)
		}
	})
}
