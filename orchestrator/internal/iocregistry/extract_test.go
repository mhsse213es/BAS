package iocregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
)

func detectionResult(commandLine, processName, threatName string) models.SimulationResult {
	return models.SimulationResult{
		DetectionAlert: &models.DetectionAlert{
			CommandLine: commandLine,
			ProcessName: processName,
			ThreatName:  threatName,
		},
	}
}

func TestExtractFromDetectionAlert_CreatesCommandLineAndProcessRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		res := detectionResult("powershell -enc AAAA", "powershell.exe", "Trojan:Win32/Meterpreter")
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", "T1059", "detected", res); err != nil {
			t.Fatalf("ExtractFromDetectionAlert: %v", err)
		}

		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM iocs`).Scan(&count); err != nil {
			t.Fatalf("count iocs: %v", err)
		}
		if count != 2 {
			t.Errorf("iocs count = %d, want 2 (command_line + process)", count)
		}

		var metaThreatName string
		if err := pool.QueryRow(context.Background(),
			`SELECT metadata->>'threatName' FROM iocs WHERE type = 'command_line' AND value = $1`,
			"powershell -enc AAAA").Scan(&metaThreatName); err != nil {
			t.Fatalf("query command_line row: %v", err)
		}
		if metaThreatName != "Trojan:Win32/Meterpreter" {
			t.Errorf("metadata.threatName = %q, want Trojan:Win32/Meterpreter", metaThreatName)
		}

		var sightingCount int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM ioc_sightings`).Scan(&sightingCount); err != nil {
			t.Fatalf("count sightings: %v", err)
		}
		if sightingCount != 2 {
			t.Errorf("ioc_sightings count = %d, want 2", sightingCount)
		}
	})
}

func TestExtractFromDetectionAlert_DedupesAcrossRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		res := detectionResult("whoami /all", "cmd.exe", "")

		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", "T1059", "detected", res); err != nil {
			t.Fatalf("first extract: %v", err)
		}
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-2", "agent-2", "T1059", "undetected", res); err != nil {
			t.Fatalf("second extract: %v", err)
		}

		var iocCount int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM iocs WHERE type = 'command_line' AND value = 'whoami /all'`).Scan(&iocCount); err != nil {
			t.Fatalf("count: %v", err)
		}
		if iocCount != 1 {
			t.Errorf("iocs rows for the same value = %d, want 1 (dedup)", iocCount)
		}

		var sightingCount int
		if err := pool.QueryRow(context.Background(), `
			SELECT COUNT(*) FROM ioc_sightings s JOIN iocs i ON i.id = s.ioc_id
			WHERE i.type = 'command_line' AND i.value = 'whoami /all'`).Scan(&sightingCount); err != nil {
			t.Fatalf("count sightings: %v", err)
		}
		if sightingCount != 2 {
			t.Errorf("sightings for the same value across 2 runs = %d, want 2", sightingCount)
		}

		var storedSightingCount int
		if err := pool.QueryRow(context.Background(),
			`SELECT sighting_count FROM iocs WHERE type = 'command_line' AND value = 'whoami /all'`).Scan(&storedSightingCount); err != nil {
			t.Fatalf("query sighting_count: %v", err)
		}
		if storedSightingCount != 2 {
			t.Errorf("iocs.sighting_count = %d, want 2", storedSightingCount)
		}
	})
}

func TestExtractFromDetectionAlert_NilAlert_NoRowsWritten(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		res := models.SimulationResult{} // DetectionAlert is nil
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", "T1059", "detected", res); err != nil {
			t.Fatalf("ExtractFromDetectionAlert: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM iocs`).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 0 {
			t.Errorf("iocs count = %d, want 0 for a nil DetectionAlert", count)
		}
	})
}

func TestExtractFromDetectionAlert_EmptyFields_Skipped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		res := detectionResult("", "svchost.exe", "") // no CommandLine
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", "T1059", "detected", res); err != nil {
			t.Fatalf("ExtractFromDetectionAlert: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM iocs`).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 1 {
			t.Errorf("iocs count = %d, want 1 (only process, empty CommandLine skipped)", count)
		}
	})
}

func TestExtractFromDetectionAlert_RecordsTechniqueAndVerdict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		res := detectionResult("net user /add evil", "net.exe", "")
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", "T1136", "prevented", res); err != nil {
			t.Fatalf("ExtractFromDetectionAlert: %v", err)
		}

		var techniqueID, verdict string
		if err := pool.QueryRow(context.Background(), `
			SELECT s.technique_id, s.detection_verdict FROM ioc_sightings s
			JOIN iocs i ON i.id = s.ioc_id WHERE i.type = 'command_line' AND i.value = 'net user /add evil'`).
			Scan(&techniqueID, &verdict); err != nil {
			t.Fatalf("query sighting: %v", err)
		}
		if techniqueID != "T1136" {
			t.Errorf("technique_id = %q, want T1136", techniqueID)
		}
		if verdict != "prevented" {
			t.Errorf("detection_verdict = %q, want prevented", verdict)
		}
	})
}
