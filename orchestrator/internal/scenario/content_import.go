package scenario

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"
)

// normalizedTest is a single execution-ready atomic test, as it will be stored
// in art_atomic_tests. It is the parsed/runtime form — no YAML, no #{...} args,
// payload-folder references already rewritten to $env:BAS_PAYLOAD_DIR.
type normalizedTest struct {
	Index            int
	Name             string
	Executor         string
	Command          string
	Cleanup          string
	Platform         string
	TimeoutSec       int
	RequiredPayloads []string
}

// normalizeAtomic parses one ART atomic YAML file into a technique ID, its
// display name, and the set of Windows-executable tests in execution-ready form.
// It mirrors the runtime transformations done in parseARTFile so the rows stored
// in art_atomic_tests are exactly what would be dispatched to an agent.
func normalizeAtomic(data []byte) (techniqueID, displayName string, tests []normalizedTest, err error) {
	var f artAtomicFile
	if err = yaml.Unmarshal(data, &f); err != nil {
		return "", "", nil, err
	}
	techniqueID = strings.ToUpper(strings.TrimSpace(f.AttackTechnique))
	if techniqueID == "" {
		return "", "", nil, fmt.Errorf("missing attack_technique")
	}
	displayName = strings.TrimSpace(f.DisplayName)

	for i, test := range f.AtomicTests {
		if !artIsWindows(test.SupportedPlatforms) {
			continue
		}
		var executor string
		switch strings.ToLower(test.Executor.Name) {
		case "powershell":
			executor = "powershell"
		case "command_prompt":
			executor = "cmd"
		default:
			continue // skip bash/sh/manual
		}

		cmd := artResolveArgs(test.Executor.Command, test.InputArguments)
		if cmd == "" {
			continue
		}
		cleanup := artResolveArgs(test.Executor.CleanupCommand, test.InputArguments)

		cmd, required := artResolvePayloads(cmd, executor)
		cleanup, _ = artResolvePayloads(cleanup, executor)

		name := fmt.Sprintf("%s - Test %d: %s", techniqueID, i+1, test.Name)
		tests = append(tests, normalizedTest{
			Index:            i,
			Name:             name,
			Executor:         executor,
			Command:          cmd,
			Cleanup:          cleanup,
			Platform:         "windows",
			TimeoutSec:       120,
			RequiredPayloads: required,
		})
	}
	return techniqueID, displayName, tests, nil
}

// SeedContent imports ART atomics (YAML) and payload metadata into Postgres.
//
// Disk is the seed source; Postgres becomes the runtime source of truth. The
// function is idempotent: a technique whose YAML hash is unchanged is skipped,
// and payload metadata is upserted. Binary payloads are NEVER copied into the
// DB — only their metadata and on-disk storage_path are recorded.
//
// If version is non-empty and matches the recorded content version (with content
// already present), the import is skipped entirely as a fast path.
func SeedContent(ctx context.Context, pool *pgxpool.Pool, atomicsDir, payloadDir, version string) (techCount, payloadCount int, err error) {
	if version != "" {
		var recVer string
		var recTech, recPayload int
		qErr := pool.QueryRow(ctx,
			`SELECT source_version, technique_count, payload_count FROM art_content_meta WHERE id = 1`,
		).Scan(&recVer, &recTech, &recPayload)
		if qErr == nil && recVer == version && recTech > 0 {
			return recTech, recPayload, nil // already seeded this version
		}
	}

	techCount, err = importAtomics(ctx, pool, atomicsDir)
	if err != nil {
		return techCount, 0, fmt.Errorf("import atomics: %w", err)
	}
	payloadCount, err = importPayloads(ctx, pool, payloadDir)
	if err != nil {
		return techCount, payloadCount, fmt.Errorf("import payloads: %w", err)
	}

	if _, err = pool.Exec(ctx,
		`INSERT INTO art_content_meta (id, source_version, technique_count, payload_count, source, imported_at)
		 VALUES (1, $1, $2, $3, 'disk-seed', NOW())
		 ON CONFLICT (id) DO UPDATE SET
		   source_version  = EXCLUDED.source_version,
		   technique_count = EXCLUDED.technique_count,
		   payload_count   = EXCLUDED.payload_count,
		   source          = EXCLUDED.source,
		   imported_at     = NOW()`,
		version, techCount, payloadCount,
	); err != nil {
		return techCount, payloadCount, fmt.Errorf("update content meta: %w", err)
	}
	return techCount, payloadCount, nil
}

// importAtomics walks atomicsDir for T*.yaml files and upserts each technique's
// raw YAML and normalized tests. Unchanged techniques (same content hash) are
// left untouched. Returns the count of techniques with at least one Windows test.
func importAtomics(ctx context.Context, pool *pgxpool.Pool, dir string) (int, error) {
	if dir == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("read atomics dir %q: %w", dir, err)
	}

	count := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, rErr := os.ReadFile(path)
		if rErr != nil {
			log.Printf("[content] skip %s: %v", e.Name(), rErr)
			continue
		}
		techniqueID, displayName, tests, nErr := normalizeAtomic(data)
		if nErr != nil {
			log.Printf("[content] skip %s: %v", e.Name(), nErr)
			continue
		}
		if len(tests) == 0 {
			continue // no Windows tests — not stored
		}

		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])

		var existing string
		_ = pool.QueryRow(ctx,
			`SELECT content_hash FROM art_atomic_raw WHERE technique_id = $1`, techniqueID,
		).Scan(&existing)
		if existing == hash {
			count++ // present and current
			continue
		}

		if err := upsertTechnique(ctx, pool, techniqueID, displayName, string(data), hash, tests); err != nil {
			log.Printf("[content] upsert %s failed: %v", techniqueID, err)
			continue
		}
		count++
	}
	return count, nil
}

// upsertTechnique writes the technique row, its raw YAML, and a fresh set of
// normalized tests within a single transaction.
func upsertTechnique(ctx context.Context, pool *pgxpool.Pool, techniqueID, displayName, rawYAML, hash string, tests []normalizedTest) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO techniques (technique_id, name, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (technique_id) DO UPDATE SET
		   name = CASE WHEN EXCLUDED.name <> '' THEN EXCLUDED.name ELSE techniques.name END,
		   updated_at = NOW()`,
		techniqueID, displayName,
	); err != nil {
		return fmt.Errorf("technique: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO art_atomic_raw (technique_id, yaml, content_hash, updated_at)
		 VALUES ($1, $2, $3, NOW())
		 ON CONFLICT (technique_id) DO UPDATE SET
		   yaml = EXCLUDED.yaml, content_hash = EXCLUDED.content_hash, updated_at = NOW()`,
		techniqueID, rawYAML, hash,
	); err != nil {
		return fmt.Errorf("raw: %w", err)
	}

	// Replace the normalized tests wholesale — indices may have shifted.
	if _, err := tx.Exec(ctx,
		`DELETE FROM art_atomic_tests WHERE technique_id = $1`, techniqueID,
	); err != nil {
		return fmt.Errorf("clear tests: %w", err)
	}
	for _, t := range tests {
		if _, err := tx.Exec(ctx,
			`INSERT INTO art_atomic_tests
			   (technique_id, test_index, name, executor, command, cleanup, platform, timeout_sec, required_payloads, framework, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'art', NOW())`,
			techniqueID, t.Index, t.Name, t.Executor, t.Command, t.Cleanup, t.Platform, t.TimeoutSec, t.RequiredPayloads,
		); err != nil {
			return fmt.Errorf("insert test %d: %w", t.Index, err)
		}
	}

	return tx.Commit(ctx)
}

// importPayloads walks payloadDir and upserts metadata for each binary it finds.
// The binary itself stays on disk; only its hash, size, type, and storage_path
// are recorded. README.md and .gitkeep are ignored.
func importPayloads(ctx context.Context, pool *pgxpool.Pool, dir string) (int, error) {
	if dir == "" {
		return 0, nil
	}
	count := 0
	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if name == "README.md" || name == ".gitkeep" {
			return nil
		}
		data, rErr := os.ReadFile(path)
		if rErr != nil {
			log.Printf("[content] payload skip %s: %v", name, rErr)
			return nil
		}
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])
		abs, aErr := filepath.Abs(path)
		if aErr != nil {
			abs = path
		}
		ptype := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")

		if _, err := pool.Exec(ctx,
			`INSERT INTO art_payloads (basename, sha256, size_bytes, storage_path, payload_type, source, updated_at)
			 VALUES ($1, $2, $3, $4, $5, 'curated', NOW())
			 ON CONFLICT (basename) DO UPDATE SET
			   sha256 = EXCLUDED.sha256, size_bytes = EXCLUDED.size_bytes,
			   storage_path = EXCLUDED.storage_path, payload_type = EXCLUDED.payload_type,
			   updated_at = NOW()`,
			strings.ToLower(name), hash, int64(len(data)), abs, ptype,
		); err != nil {
			log.Printf("[content] payload upsert %s failed: %v", name, err)
			return nil
		}
		count++
		return nil
	})
	if walkErr != nil {
		return count, walkErr
	}
	return count, nil
}
