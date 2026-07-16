# SP5 — Layered Threat-Intel Fetch Implementation Plan

> **For agentic workers:** implement task-by-task, TDD. Steps use `- [ ]`.

**Goal:** Add a signed air-gapped bundle source to the existing live TI connector so it runs with zero internet and overlays live MISP/OpenCTI when available.

**Architecture:** `Source` interface (Fetch/Name) implemented by MISPClient, OpenCTIClient, and a new BundleSource; Scheduler iterates `sources []Source`; existing `mergeActors` + `Generator` reused unchanged. Bundle verified via `integrity.VerifyScenarioFile` (injected for testability).

**Tech Stack:** Go 1.26, `internal/connector`, `internal/integrity`, encoding/json.

---

### Task 1: `Source` interface + json tags + adapters

**Files:** Create `orchestrator/internal/connector/source.go`; Modify `types.go`, `misp.go`, `opencti.go`.

- [ ] Add json tags to `ThreatActor` + `TechniqueRef` in `types.go` (garble-safe bundle JSON).
- [ ] `source.go`:
```go
package connector

// Source is one threat-intel provider (live MISP/OpenCTI or an air-gapped bundle).
type Source interface {
	Fetch() ([]ThreatActor, error)
	Name() string
}
```
- [ ] `misp.go`: `func (c *MISPClient) Name() string { return "misp" }`
- [ ] `opencti.go`: `func (c *OpenCTIClient) Name() string { return "opencti" }`
- [ ] `go build ./internal/connector/...` → passes.

### Task 2: BundleSource (TDD)

**Files:** Create `bundle.go`, `bundle_test.go`.

- [ ] Write `bundle_test.go` first: valid bundle (injected verify returns nil) → actors parsed; verify returns error → Fetch errors, no actors; missing file → error; malformed JSON → error; `Version()` reflects parsed version.
- [ ] `bundle.go`:
```go
type Bundle struct {
	Version     string        `json:"version"`
	GeneratedAt time.Time     `json:"generated_at"`
	Actors      []ThreatActor `json:"actors"`
}

type BundleSource struct {
	path    string
	verify  func(path string) error
	version string
}

func NewBundleSource(dir string, verify func(string) error) *BundleSource {
	return &BundleSource{path: filepath.Join(dir, "ti-bundle.json"), verify: verify}
}

func (b *BundleSource) Name() string    { return "bundle" }
func (b *BundleSource) Version() string  { return b.version }

func (b *BundleSource) Fetch() ([]ThreatActor, error) {
	if b.verify != nil {
		if err := b.verify(b.path); err != nil {
			return nil, fmt.Errorf("ti bundle verify: %w", err)
		}
	}
	raw, err := os.ReadFile(b.path)
	if err != nil { return nil, fmt.Errorf("read ti bundle: %w", err) }
	var bundle Bundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("parse ti bundle: %w", err)
	}
	b.version = bundle.Version
	return bundle.Actors, nil
}
```
- [ ] `go test ./internal/connector/...` → passes.

### Task 3: Scheduler refactor to `[]Source`

**Files:** Modify `scheduler.go`, `types.go` (status fields); Test `scheduler_test.go`.

- [ ] `types.go` `ConnectorStatus`: add `BundleEnabled bool json:"bundleEnabled"`, `BundleVersion string json:"bundleVersion,omitempty"`.
- [ ] `scheduler.go`: replace `misp`/`opencti` fields with `sources []Source`; `NewScheduler(sources []Source, generator *Generator, engine *scenario.Engine, pollHours int)`; `Start()` idles when `len(sources)==0`; `sync()` iterates `for _, src := range s.sources { src.Fetch() … }`; set `status.MISPEnabled/OpenCTIEnabled/BundleEnabled` from source names; after a bundle fetch, `if bs, ok := src.(*BundleSource); ok { status.BundleVersion = bs.Version() }`.
- [ ] Write `scheduler_test.go`: fake `Source` returning canned actors; two sources merge; empty → idle.
- [ ] `go test ./internal/connector/...` → passes.

### Task 4: Config + main wiring + compose

**Files:** Modify `config/config.go`, `cmd/server/main.go`, `packaging/compose/docker-compose.yml`.

- [ ] `config.go`: add `TIBundleDir string json:"ti_bundle_dir,omitempty"` + `os.Getenv("TI_BUNDLE_DIR")` (default `/intel-bundles`).
- [ ] `main.go` (around L193-205): build `sources := []connector.Source{}`; append misp/opencti when configured; append `connector.NewBundleSource(cfg.TIBundleDir, integrity.VerifyScenarioFile)` when the bundle file exists; `connector.NewScheduler(sources, gen, engine, cfg.ThreatIntelPollHours)`.
- [ ] `docker-compose.yml`: add `TI_BUNDLE_DIR: ${TI_BUNDLE_DIR:-/intel-bundles}` env + `- ${TI_BUNDLE_DIR_HOST:-./intel-bundles}:/intel-bundles:ro` volume.
- [ ] `gofmt -w` touched files; `go build ./...`; `go vet ./internal/connector/... ./cmd/server/...`; `go test ./internal/connector/...`.

### Task 5: Capture + commit

- [ ] Update vault: `Threat Intel Pipeline` note → `in-progress`, Implementation Status; new ADR `ADR-008 TI Layered Fetch`; daily note 2026-07-17.
- [ ] Commit spec+plan+code; push.
