# D3FEND countermeasures on ATT&CK enrichment: QA log

## Source
- File: MITRE D3FEND ATT&CK mapping, `d3fend-full-mappings.csv`, D3FEND 1.6.0, downloaded from `https://d3fend.mitre.org/ontologies/d3fend/1.6.0/d3fend-full-mappings.csv` (14.7 MB).
- SHA-256 of the CSV: see the command output recorded in the commit message.
- Terms: MITRE D3FEND Terms of Use (`https://d3fend.mitre.org/tou`). Non-exclusive, royalty-free licence for research, development and commercial use, provided MITRE's copyright designation and licence are reproduced in every copy. The notice is `attackdata.D3fendAttribution` and is shown on every technique that lists countermeasures. Government contracts also cite DFARS 252.227-7014; a government-customer review is still open.
- The repository code (`d3fend/d3fend-ontology`) is MIT.

## Normalisation (committed as `orchestrator/internal/reporting/attackdata/d3fend-attack-map.json`)
- Each row's `off_tech_id` is the ATT&CK ID; `def_tech` IRI resolved to its `D3-…` ID through `d3fend.json`. All 157 defensive techniques resolved.
- 35 keys were dropped because they are D3FEND detection/analytic IDs (`DE-…`, `EX-…`), not ATT&CK techniques.
- Result: 392 ATT&CK technique IDs, 3,927 (technique, countermeasure) pairs.
- The mapping is MITRE's inference over shared artifacts. It is not hand-curated, so each countermeasure is a derived association, not a verified claim.

## Regeneration
- Bundle: ATT&CK 16.1 `enterprise-attack-16.1.json`, SHA-256 `8423d8dac3fc2feb825bb07d26e5f5d905e08a88f6fe4652cc20834cbe982813`, matches `attack_dataset_meta.json`.
- Command: `go run ./internal/reporting/attackdata/gen enterprise-attack-16.1.json internal/reporting/attackdata/attack_enrichment.json --d3fend=internal/reporting/attackdata/d3fend-attack-map.json`
- Diff against the previous enrichment: 656 techniques, 322 gained countermeasures, no other field changed.

## Coverage
- 322 of the 392 mapped IDs exist in the ATT&CK 16.1 dataset. 70 IDs come from a newer ATT&CK version; they appear once the dataset is upgraded.

## Tests run
- `go test ./internal/reporting/attackdata/ ./internal/reporting/` pass (red-green on `TestLookupD3fendCountermeasures` and `TestD3fendAttributionNamesMITRE`).
- `go test ./internal/reporting/attackdata/gen/` passes.
- `go build ./...` passes. `go test ./internal/api/ -run "Attack|Technique|Coverage|Finding|Enrich"` passes.
- `go vet ./internal/reporting/...` is clean.

## Not verified
- A rendered PDF with a D3FEND line has not been visually checked.
- The D3FEND countermeasures do not yet appear in the console UI, only in the PDF technique block and the ATT&CK API payload.
- REQ-048 scores "Heatmap + Navigator layer export; no D3FEND". This closes the data side only. A heatmap or Navigator layer that uses the D3FEND field is not built.
