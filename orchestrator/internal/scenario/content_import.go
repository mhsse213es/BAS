package scenario

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/models"
)

// normalizedTest is a single execution-ready atomic test, as it will be stored
// in art_atomic_tests. It is the parsed/runtime form — no YAML, no #{...} args,
// payload-folder references already rewritten to $env:BAS_PAYLOAD_DIR.
type normalizedTest struct {
	Index                     int
	Name                      string
	Executor                  string
	Command                   string
	Cleanup                   string
	Platform                  string
	TimeoutSec                int
	RequiredPayloads          []string
	RequiresPriv              PrivSpec
	OriginalElevationRequired bool
}

// normalizeAtomic parses one ART atomic YAML file into a technique ID, its
// display name, and all execution-ready tests (Windows + Linux/macOS).
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

	// ── Windows atomics ──────────────────────────────────────────────────────
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
			continue
		}
		cmd := artResolveArgs(test.Executor.Command, test.InputArguments, techniqueID, test.Name)
		if cmd == "" {
			continue
		}
		cleanup := artResolveArgs(test.Executor.CleanupCommand, test.InputArguments, techniqueID, test.Name)
		cmd, required := artResolvePayloads(cmd, executor)
		cleanup, _ = artResolvePayloads(cleanup, executor)
		name := fmt.Sprintf("%s - Test %d: %s", techniqueID, i+1, test.Name)
		tests = append(tests, normalizedTest{
			Index: i, Name: name, Executor: executor,
			Command: cmd, Cleanup: cleanup, Platform: "windows",
			TimeoutSec: 120, RequiredPayloads: required,
			RequiresPriv:              mapARTElevation(test.Executor.ElevationRequired),
			OriginalElevationRequired: test.Executor.ElevationRequired,
		})
	}

	// ── Linux / macOS atomics ────────────────────────────────────────────────
	for i, test := range f.AtomicTests {
		platform := artUnixPlatform(test.SupportedPlatforms)
		if platform == "" {
			continue
		}
		switch strings.ToLower(test.Executor.Name) {
		case "bash", "sh", "zsh", "fish":
		default:
			continue
		}
		cmd := artResolveArgs(test.Executor.Command, test.InputArguments, techniqueID, test.Name)
		if cmd == "" {
			continue
		}
		cleanup := artResolveArgs(test.Executor.CleanupCommand, test.InputArguments, techniqueID, test.Name)
		cmd, required := artResolvePayloadsUnix(cmd)
		cleanup, _ = artResolvePayloadsUnix(cleanup)
		name := fmt.Sprintf("%s - Test %d: %s", techniqueID, i+1, test.Name)
		tests = append(tests, normalizedTest{
			Index: i, Name: name, Executor: "bash",
			Command: cmd, Cleanup: cleanup, Platform: platform,
			TimeoutSec: 120, RequiredPayloads: required,
			RequiresPriv:              mapARTElevation(test.Executor.ElevationRequired),
			OriginalElevationRequired: test.Executor.ElevationRequired,
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
// already present), the import is skipped entirely as a fast path — unless force
// is set (used by the admin reseed endpoint to apply a dropped content pack).
func SeedContent(ctx context.Context, pool *pgxpool.Pool, atomicsDir, payloadDir, kevFile, version string, force bool) (techCount, payloadCount int, err error) {
	// Tactic reference + technique→tactic backfill are cheap and idempotent, so
	// run them on every boot (independent of the content-version fast-path) to
	// keep the knowledge graph populated even when atomics are unchanged.
	if err := seedTactics(ctx, pool); err != nil {
		log.Printf("[content] seed tactics: %v", err)
	}
	if n, err := backfillTechniqueTactics(ctx, pool); err != nil {
		log.Printf("[content] backfill technique tactics: %v", err)
	} else if n > 0 {
		log.Printf("[content] tactic backfill updated %d techniques", n)
	}
	if err := seedOWASP(ctx, pool); err != nil {
		log.Printf("[content] seed OWASP risks: %v", err)
	}
	if n, err := backfillTechniqueOWASP(ctx, pool); err != nil {
		log.Printf("[content] backfill technique OWASP: %v", err)
	} else if n > 0 {
		log.Printf("[content] OWASP backfill added %d technique links", n)
	}
	if n, err := seedCVEs(ctx, pool, kevFile); err != nil {
		log.Printf("[content] seed CISA KEV: %v", err)
	} else if n > 0 {
		log.Printf("[content] CISA KEV catalog: %d CVEs seeded", n)
	}
	if n, err := backfillTechniqueCVEs(ctx, pool); err != nil {
		log.Printf("[content] backfill technique CVEs: %v", err)
	} else if n > 0 {
		log.Printf("[content] CVE backfill added %d technique links", n)
	}
	if n, err := seedRelationshipsFromLegacyCVEs(ctx, pool); err != nil {
		log.Printf("[content] seed CVE relationships: %v", err)
	} else if n > 0 {
		log.Printf("[content] Relationship Store: migrated %d technique-CVE relationships", n)
	}

	if !force && version != "" {
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

// currentARTImportVersion identifies the ART importer's normalization format.
// Bump this whenever normalizeAtomic starts populating a new field from raw
// ART data — every already-seeded technique will then be automatically
// re-normalized and re-upserted on the next boot, even though its underlying
// YAML content hash hasn't changed. v1: original import (no privilege data).
// v2: adds requires_priv / original_elevation_required (this fix).
const currentARTImportVersion = 2

// shouldReimportTechnique reports whether a technique needs a fresh
// normalize-and-upsert pass: either its raw YAML content changed, or it was
// last imported by an older importer format and needs upgrading even though
// the content itself is unchanged.
func shouldReimportTechnique(existingHash, newHash string, existingVersion int) bool {
	return existingHash != newHash || existingVersion < currentARTImportVersion
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

		var existingHash string
		var existingVersion int
		_ = pool.QueryRow(ctx,
			`SELECT content_hash, import_version FROM art_atomic_raw WHERE technique_id = $1`, techniqueID,
		).Scan(&existingHash, &existingVersion)
		if !shouldReimportTechnique(existingHash, hash, existingVersion) {
			count++ // present, current content, and imported at the current parser version
			continue
		}

		tactic := models.LookupTactic(techniqueID)
		if err := upsertTechnique(ctx, pool, techniqueID, displayName, tactic, string(data), hash, tests); err != nil {
			log.Printf("[content] upsert %s failed: %v", techniqueID, err)
			continue
		}
		count++
	}
	return count, nil
}

// upsertTechnique writes the technique row, its raw YAML, and a fresh set of
// normalized tests within a single transaction.
func upsertTechnique(ctx context.Context, pool *pgxpool.Pool, techniqueID, displayName, tactic, rawYAML, hash string, tests []normalizedTest) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO techniques (technique_id, name, tactic, updated_at)
		 VALUES ($1, $2, $3, NOW())
		 ON CONFLICT (technique_id) DO UPDATE SET
		   name = CASE WHEN EXCLUDED.name <> '' THEN EXCLUDED.name ELSE techniques.name END,
		   tactic = CASE WHEN EXCLUDED.tactic <> '' THEN EXCLUDED.tactic ELSE techniques.tactic END,
		   updated_at = NOW()`,
		techniqueID, displayName, tactic,
	); err != nil {
		return fmt.Errorf("technique: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO art_atomic_raw (technique_id, yaml, content_hash, import_version, updated_at)
		 VALUES ($1, $2, $3, $4, NOW())
		 ON CONFLICT (technique_id) DO UPDATE SET
		   yaml = EXCLUDED.yaml, content_hash = EXCLUDED.content_hash,
		   import_version = EXCLUDED.import_version, updated_at = NOW()`,
		techniqueID, rawYAML, hash, currentARTImportVersion,
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
		// required_payloads is NOT NULL; most tests need no payload, so the
		// slice is nil here. pgx encodes a nil slice as SQL NULL (which would
		// violate the constraint and roll back the whole technique), so send an
		// empty array instead.
		payloads := t.RequiredPayloads
		if payloads == nil {
			payloads = []string{}
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO art_atomic_tests
			   (technique_id, test_index, name, executor, command, cleanup, platform, timeout_sec, required_payloads, framework, requires_priv, original_elevation_required, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'art', $10, $11, NOW())`,
			techniqueID, t.Index, t.Name, t.Executor, t.Command, t.Cleanup, t.Platform, t.TimeoutSec, payloads,
			t.RequiresPriv.Effective(), t.OriginalElevationRequired,
		); err != nil {
			return fmt.Errorf("insert test %d: %w", t.Index, err)
		}
	}

	return tx.Commit(ctx)
}

// payloadExtAllow is the set of file extensions treated as ART external payloads.
// The staging folder on a build host often also contains tool source trees, zip
// archives, installers, PDBs and license files — none of which an atomic invokes.
// Only real executables/scripts are indexed so the bundle and DB stay clean.
var payloadExtAllow = map[string]bool{
	".exe": true, ".dll": true, ".ps1": true, ".psm1": true, ".bat": true,
	".cmd": true, ".vbs": true, ".js": true, ".hta": true, ".sys": true,
	".com": true, ".scr": true, ".jar": true, ".py": true, ".sh": true,
}

// isPayloadFile reports whether name has an allowlisted payload extension.
func isPayloadFile(name string) bool {
	return payloadExtAllow[strings.ToLower(filepath.Ext(name))]
}

// importPayloads walks payloadDir and upserts metadata for each payload binary it
// finds. Only allowlisted executables/scripts are indexed; source, archives and
// docs are ignored. The binary itself stays on disk; only its hash, size, type
// and storage_path are recorded. Duplicate basenames (the same tool present in
// several extracted folders) are resolved first-wins, with a warning.
func importPayloads(ctx context.Context, pool *pgxpool.Pool, dir string) (int, error) {
	if dir == "" {
		return 0, nil
	}
	count := 0
	seen := make(map[string]string) // lowercase basename -> first path used
	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if !isPayloadFile(name) {
			return nil
		}
		key := strings.ToLower(name)
		if first, dup := seen[key]; dup {
			log.Printf("[content] payload duplicate %q ignored (keeping %s, skipping %s)", name, first, path)
			return nil
		}
		seen[key] = path
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

// MissingPayloads returns the distinct payload basenames that loaded atomics
// reference but which are absent from art_payloads — i.e. the external binaries
// an operator would need to add (or rename to match) to enable those tests.
// Basenames are returned lowercased and sorted; matching is case-insensitive, so
// these are the exact filenames to rename a binary to. An atomic whose payload is
// missing is skipped cleanly at dispatch, so this list is advisory, not an error.
func MissingPayloads(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	rows, err := pool.Query(ctx,
		`SELECT DISTINCT lower(rp) AS needed
		   FROM art_atomic_tests t, unnest(t.required_payloads) AS rp
		  WHERE lower(rp) NOT IN (SELECT basename FROM art_payloads)
		  ORDER BY needed`)
	if err != nil {
		return nil, fmt.Errorf("query missing payloads: %w", err)
	}
	defer rows.Close()
	var missing []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		missing = append(missing, name)
	}
	return missing, rows.Err()
}

// kevCatalog mirrors the CISA Known Exploited Vulnerabilities JSON feed. Only the
// fields we store are decoded; the rest of the feed is ignored.
type kevCatalog struct {
	CatalogVersion  string    `json:"catalogVersion"`
	Vulnerabilities []kevVuln `json:"vulnerabilities"`
}

type kevVuln struct {
	CveID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	ShortDescription  string `json:"shortDescription"`
	DateAdded         string `json:"dateAdded"`                  // YYYY-MM-DD
	KnownRansomware   string `json:"knownRansomwareCampaignUse"` // "Known" | "Unknown"
}

// seedCVEs loads the CISA KEV catalog from kevFile and upserts every entry into
// the cves table (source = 'cisa-kev'). The file is baked into the image at build
// time; a missing/empty path is not an error — KEV enrichment is simply skipped.
// Upserts are pipelined in a single batch so the ~1.4k-row catalog seeds quickly
// on boot. Returns the number of CVEs upserted.
func seedCVEs(ctx context.Context, pool *pgxpool.Pool, kevFile string) (int, error) {
	if kevFile == "" {
		return 0, nil
	}
	data, err := os.ReadFile(kevFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[content] CISA KEV file %q absent — skipping CVE enrichment", kevFile)
			return 0, nil
		}
		return 0, fmt.Errorf("read KEV file %q: %w", kevFile, err)
	}
	var cat kevCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return 0, fmt.Errorf("parse KEV file %q: %w", kevFile, err)
	}
	if len(cat.Vulnerabilities) == 0 {
		return 0, nil
	}

	const upsert = `INSERT INTO cves
	   (cve_id, description, name, vendor, product, date_added, known_ransomware, source, updated_at)
	 VALUES ($1, $2, $3, $4, $5, $6, $7, 'cisa-kev', NOW())
	 ON CONFLICT (cve_id) DO UPDATE SET
	   description = EXCLUDED.description, name = EXCLUDED.name,
	   vendor = EXCLUDED.vendor, product = EXCLUDED.product,
	   date_added = EXCLUDED.date_added, known_ransomware = EXCLUDED.known_ransomware,
	   source = EXCLUDED.source, updated_at = NOW()`

	batch := &pgx.Batch{}
	for _, v := range cat.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CveID))
		if id == "" {
			continue
		}
		var dateAdded *time.Time
		if t, perr := time.Parse("2006-01-02", strings.TrimSpace(v.DateAdded)); perr == nil {
			dateAdded = &t
		}
		ransom := strings.EqualFold(strings.TrimSpace(v.KnownRansomware), "Known")
		batch.Queue(upsert, id, v.ShortDescription, v.VulnerabilityName,
			v.VendorProject, v.Product, dateAdded, ransom)
	}
	if batch.Len() == 0 {
		return 0, nil
	}

	br := pool.SendBatch(ctx, batch)
	defer br.Close()
	count := 0
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			return count, fmt.Errorf("upsert KEV entry %d: %w", i, err)
		}
		count++
	}
	return count, nil
}

// backfillTechniqueCVEs links each technique present in the DB to the curated
// CISA KEV CVEs it relates to (models.LookupCVEs). The link is created only when
// the CVE actually exists in the seeded cves table, so an unknown/retired CVE in
// the curated map is silently skipped and the FK on technique_cves always holds.
// Additive and idempotent (ON CONFLICT DO NOTHING). Returns links inserted.
func backfillTechniqueCVEs(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	rows, err := pool.Query(ctx, `SELECT technique_id FROM techniques`)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	inserted := 0
	for _, id := range ids {
		for _, cve := range models.LookupCVEs(id) {
			tag, err := pool.Exec(ctx,
				`INSERT INTO technique_cves (technique_id, cve_id)
				 SELECT $1, $2
				 WHERE EXISTS (SELECT 1 FROM cves WHERE cve_id = $2)
				 ON CONFLICT DO NOTHING`,
				id, cve,
			)
			if err != nil {
				return inserted, err
			}
			inserted += int(tag.RowsAffected())
		}
	}
	return inserted, nil
}

// seedRelationshipsFromLegacyCVEs converts each (technique_id, cve_id) pair
// already present in technique_cves into a relationship in
// technique_cve_relationships, for pairs that don't have one yet. This is the
// one-time migration path from the old bare join to the evidence-backed
// Relationship Store: legacy links carry no provenance beyond "someone curated
// this", so they land as relationship_type=Commonly Associated,
// confidence=Medium, primary_source=Migrated, with a single evidence item
// recording the legacy origin. Additive and idempotent — the unique constraint
// on (technique_id, cve_id, relationship_type) makes re-runs no-ops.
func seedRelationshipsFromLegacyCVEs(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	rows, err := pool.Query(ctx, `
		SELECT tc.technique_id, tc.cve_id FROM technique_cves tc
		WHERE NOT EXISTS (
			SELECT 1 FROM technique_cve_relationships r
			WHERE r.technique_id = tc.technique_id AND r.cve_id = tc.cve_id
			  AND r.relationship_type = 'Commonly Associated'
		)`)
	if err != nil {
		return 0, err
	}
	type pair struct{ techID, cveID string }
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.techID, &p.cveID); err != nil {
			rows.Close()
			return 0, err
		}
		pairs = append(pairs, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	inserted := 0
	for _, p := range pairs {
		var relID string
		err := pool.QueryRow(ctx, `
			INSERT INTO technique_cve_relationships
				(technique_id, cve_id, relationship_type, proposed_confidence,
				 effective_confidence, primary_source, rationale, created_by, updated_by)
			VALUES ($1,$2,'Commonly Associated','Medium','Medium','Migrated',
				'Migrated from the legacy curated CVE mapping.','migration','migration')
			ON CONFLICT (technique_id, cve_id, relationship_type) DO NOTHING
			RETURNING id`, p.techID, p.cveID).Scan(&relID)
		if err != nil {
			if err == pgx.ErrNoRows {
				continue // ON CONFLICT DO NOTHING hit — already migrated
			}
			return inserted, err
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO relationship_evidence
				(relationship_id, source, reference_type, reference_value, note, added_by)
			VALUES ($1,'Migrated','Internal Note','',
				'Carried over from technique_cves at Relationship Store migration.','migration')`,
			relID); err != nil {
			return inserted, err
		}
		inserted++
	}
	return inserted, nil
}

// SeedEPSS reads the FIRST EPSS CSV/CSV.GZ file and upserts exploitation-probability
// scores into cve_epss for CVEs that are linked to techniques in technique_cves.
// Only relevant CVEs are inserted — the full EPSS catalog (~220k rows) is NOT bulk-loaded.
// File format: comment lines starting with '#', then header 'cve,epss,percentile', then data.
// No-op when the file does not exist; silently tolerates an empty technique_cves table.
func SeedEPSS(ctx context.Context, pool *pgxpool.Pool, epssFile string) (int, error) {
	if epssFile == "" {
		return 0, nil
	}

	// Get the CVE IDs we actually care about (in technique_cves)
	cveRows, err := pool.Query(ctx, `SELECT DISTINCT cve_id FROM technique_cves`)
	if err != nil {
		return 0, fmt.Errorf("query technique_cves: %w", err)
	}
	ourCVEs := map[string]bool{}
	for cveRows.Next() {
		var id string
		if cveRows.Scan(&id) == nil {
			ourCVEs[strings.ToUpper(id)] = true
		}
	}
	cveRows.Close()
	if len(ourCVEs) == 0 {
		log.Printf("[content] EPSS seed skipped — no CVEs in technique_cves yet")
		return 0, nil
	}

	f, err := os.Open(epssFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[content] EPSS file %q absent — skipping EPSS enrichment", epssFile)
			return 0, nil
		}
		return 0, fmt.Errorf("open EPSS file %q: %w", epssFile, err)
	}
	defer f.Close()

	var rd io.Reader = f
	if strings.HasSuffix(strings.ToLower(epssFile), ".gz") {
		gr, gerr := gzip.NewReader(f)
		if gerr != nil {
			return 0, fmt.Errorf("open EPSS gzip %q: %w", epssFile, gerr)
		}
		defer gr.Close()
		rd = gr
	}

	const upsert = `INSERT INTO cve_epss (cve_id, epss_score, percentile, score_date, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (cve_id) DO UPDATE SET
			epss_score = EXCLUDED.epss_score,
			percentile = EXCLUDED.percentile,
			score_date = EXCLUDED.score_date,
			updated_at = NOW()`

	type epssEntry struct {
		score, percentile float64
		scoreDate         *time.Time
	}
	matches := make(map[string]epssEntry, len(ourCVEs))

	scanner := bufio.NewScanner(rd)
	scanner.Buffer(make([]byte, 512*1024), 512*1024)
	var scoreDate *time.Time
	headerSeen := false

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "#score_date:") {
				ds := strings.TrimPrefix(line, "#score_date:")
				if t, terr := time.Parse(time.RFC3339, strings.TrimSpace(ds)); terr == nil {
					td := t
					scoreDate = &td
				}
			}
			continue
		}
		if !headerSeen {
			headerSeen = true // skip "cve,epss,percentile" header
			continue
		}
		parts := strings.SplitN(line, ",", 3)
		if len(parts) != 3 {
			continue
		}
		cveID := strings.ToUpper(strings.TrimSpace(parts[0]))
		if !ourCVEs[cveID] {
			continue
		}
		var sc, pct float64
		fmt.Sscanf(parts[1], "%f", &sc)
		fmt.Sscanf(parts[2], "%f", &pct)
		matches[cveID] = epssEntry{sc, pct, scoreDate}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scan EPSS CSV: %w", err)
	}
	if len(matches) == 0 {
		log.Printf("[content] EPSS file %q produced no matches for our CVE set", epssFile)
		return 0, nil
	}

	batch := &pgx.Batch{}
	for cveID, e := range matches {
		batch.Queue(upsert, cveID, e.score, e.percentile, e.scoreDate)
	}
	br := pool.SendBatch(ctx, batch)
	count := 0
	for i := 0; i < batch.Len(); i++ {
		if tag, berr := br.Exec(); berr == nil {
			count += int(tag.RowsAffected())
		}
	}
	br.Close()
	return count, nil
}

// seedTactics upserts the 14 ATT&CK Enterprise tactics into the tactics table.
// Idempotent — the reference set is the canonical list in the models package.
func seedTactics(ctx context.Context, pool *pgxpool.Pool) error {
	for _, t := range models.EnterpriseTactics {
		if _, err := pool.Exec(ctx,
			`INSERT INTO tactics (tactic_id, name, attack_id, kill_chain_order, updated_at)
			 VALUES ($1, $2, $3, $4, NOW())
			 ON CONFLICT (tactic_id) DO UPDATE SET
			   name = EXCLUDED.name, attack_id = EXCLUDED.attack_id,
			   kill_chain_order = EXCLUDED.kill_chain_order, updated_at = NOW()`,
			t.ID, t.Name, t.AttackID, t.Order,
		); err != nil {
			return fmt.Errorf("tactic %s: %w", t.ID, err)
		}
	}
	return nil
}

// backfillTechniqueTactics fills techniques.tactic from the in-code ATT&CK map
// for any rows where it is currently empty or stale. Returns the number updated.
// This keeps the DB knowledge graph consistent with runtime scoring even for
// techniques whose YAML did not change (so the importer skipped them).
func backfillTechniqueTactics(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	rows, err := pool.Query(ctx, `SELECT technique_id, tactic FROM techniques`)
	if err != nil {
		return 0, err
	}
	type pair struct{ id, want string }
	var updates []pair
	for rows.Next() {
		var id, cur string
		if err := rows.Scan(&id, &cur); err != nil {
			rows.Close()
			return 0, err
		}
		want := models.LookupTactic(id)
		if want != "" && want != cur {
			updates = append(updates, pair{id, want})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, u := range updates {
		if _, err := pool.Exec(ctx,
			`UPDATE techniques SET tactic = $2, updated_at = NOW() WHERE technique_id = $1`,
			u.id, u.want,
		); err != nil {
			return 0, err
		}
	}
	return len(updates), nil
}

// seedOWASP upserts the OWASP Top 10 (2021) categories into the owasp_risks
// table. Idempotent — the canonical set lives in the models package.
func seedOWASP(ctx context.Context, pool *pgxpool.Pool) error {
	for _, r := range models.OWASP2021 {
		if _, err := pool.Exec(ctx,
			`INSERT INTO owasp_risks (risk_id, version, name, display_order, updated_at)
			 VALUES ($1, $2, $3, $4, NOW())
			 ON CONFLICT (risk_id) DO UPDATE SET
			   version = EXCLUDED.version, name = EXCLUDED.name,
			   display_order = EXCLUDED.display_order, updated_at = NOW()`,
			r.ID, r.Version, r.Name, r.Order,
		); err != nil {
			return fmt.Errorf("owasp %s: %w", r.ID, err)
		}
	}
	return nil
}

// backfillTechniqueOWASP links each technique present in the DB to the OWASP 2021
// categories it relates to, per the curated map in the models package. Additive
// and idempotent (ON CONFLICT DO NOTHING). Returns the number of links inserted.
// Only techniques that exist in the techniques table are linked, so the FK on
// technique_owasp is always satisfied.
func backfillTechniqueOWASP(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	rows, err := pool.Query(ctx, `SELECT technique_id FROM techniques`)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	inserted := 0
	for _, id := range ids {
		for _, risk := range models.LookupOWASP(id) {
			tag, err := pool.Exec(ctx,
				`INSERT INTO technique_owasp (technique_id, risk_id)
				 VALUES ($1, $2) ON CONFLICT DO NOTHING`,
				id, risk,
			)
			if err != nil {
				return inserted, err
			}
			inserted += int(tag.RowsAffected())
		}
	}
	return inserted, nil
}
