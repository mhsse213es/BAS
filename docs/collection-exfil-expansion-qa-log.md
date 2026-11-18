# Collection → Staging → Exfiltration Expansion: QA Log

Scenario upgrade #3, driven by the collection chain review. Scope: 20 new DLP
scenarios, fixes to three existing ATT&CK mappings, a chain report, and a console
panel.

## Verified

- **Schema:** every new file loads through `scenario.ParseYAML` and `Validate`.
- **PowerShell syntax:** every command and cleanup block parses under the Windows
  PowerShell parser. Blocks were parsed, not executed.
- **Signatures:** every new file is signed; `verify-all` reports ok=233, fail=0.
- **Step-contract ledger:** regenerated after each addition with no entries
  removed; `TestStepContract_*` pass.
- **Verdict form:** every verdict line uses `WORD:`; `TestVerdictTokens_ExactForm` passes.
- **Product lines:** every scenario has a licensed product line;
  `TestBuiltinScenarios_AllHaveValidProductLine` passes.
- **Chain report:** `internal/exfilchain` unit tests pass (7); the API route and
  handler tests pass.
- **Console panel:** `exfil-chain.js` unit tests pass (8); the full web suite passes
  (915); the production build passes; lint has 0 errors.

## Scenarios (20)

| Scenario | Coverage | Techniques |
|---|---|---|
| collection-network-share-exfil | local share discovery, read-only listing, manifest upload | T1135, T1039, T1048.003 |
| collection-database-export-exfil | synthetic table dump, archive, upload | T1005, T1560.001, T1048.003 |
| collection-pii-financial-exfil | published test identifiers, staging, DLP content inspection | T1005, T1074.001, T1048.003 |
| collection-encrypted-archive-exfil | 7-Zip AES-256 archive, upload over plain HTTP | T1560.001, T1048.003 |
| collection-cloud-storage-exfil | staging, object-storage PUT attempt | T1074.001, T1567.002 |
| collection-low-and-slow-exfil | eight chunks at a steady interval, about 25 s | T1074.001, T1029 |
| collection-removable-media-exfil | removable-volume discovery, one synthetic file | T1120, T1052.001 |
| collection-email-mailbox-exfil | synthetic .eml export, archive, upload | T1114.001, T1560.001, T1048.003 |
| collection-masquerade-cleanup-exfil | benign-name copy, original removed, upload | T1036, T1070.004, T1048.003 |
| collection-sensitive-discovery | sensitive extensions, database files, read-only | T1083 |
| collection-source-code-exfil | synthetic source tree, archive, code-host push | T1005, T1560.001, T1567.001 |
| collection-large-volume-transfer | 20 MB staging, one upload attempt | T1074.001, T1048.003 |
| collection-channel-variants-exfil | SFTP, SMB, C2 beacon, cloud API | T1048.002, T1048.003, T1041, T1567.002 |
| collection-archive-split-exfil | 1 MB volume split, one volume sent | T1560.001, T1048.003 |
| collection-browser-cloud-email-discovery | browser profiles, cloud-sync folders, mail stores | T1217, T1619, T1114 |
| collection-hidden-staging-manifest-exfil | hidden staging, manifest with hashes, upload | T1074.001, T1048.003 |
| collection-multidir-automated-exfil | decoys in three folders, scripted collection, summary | T1005, T1048.003 |
| collection-clipboard-exfil | presence check; capture only on an empty clipboard, cleared afterwards | T1115, T1048.003 |
| collection-remote-share-discovery | share enumeration on one named target, listing | T1135, T1039 |
| collection-encrypted-blob-detection | high-entropy archive-named file, upload | T1027, T1048.003 |

All data is synthetic (`[BAS-SIM]`) or read-only. Every destination is an
RFC-6761 `.invalid` host, except the remote share target, which the operator sets
or which defaults to `.invalid`.

## Fixes to existing scenarios

- **collection-staging-exfil** mappings corrected (`0de8cb71`): stage 6 name matches
  its tag T1048.003; stage 7 (hex-encoded DNS) T1048.001 → T1048.003; stage 9
  (WebDAV) generic T1048 → T1048.003. Ledger entries updated.

## Decisions

- **Email attachment exfiltration:** not built. `dlp-exfiltration-smtp` covers it.
- **Web-service API upload (T1567.001):** not built separately.
  `collection-source-code-exfil` uses the technique for a code-host push.
- **Clipboard collection (T1115):** built, with a design that never reads user
  content. It runs only on an empty clipboard, clears its own marker, and
  restores the empty state. Clipboard history may still record the marker.
- **Remote share discovery:** scoped to one target named by the operator; it never
  scans a range.
- **Exfiltration correlation:** a report only (`GET /exfil-chain`, console panel).
  The campaign table is on hold until a live run shows the report is worth building.
- **Archive encryption detection:** covered by `collection-encrypted-blob-detection`,
  which tests the detection side. It is not a separate archive.

## Not verified

- **No new scenario has run on a host.** All twenty are checked offline only. The
  first real test needs the rebuild and a run on the lab VM.
- **Chain and efficacy panels** have not been checked in a browser.
- **Chain report** has not been checked against a real exfiltration run.

## Known issues

- **AppControl WMI proxy test** failed once in a full package run and did not
  reproduce in nine runs since. The runner now reports process errors, so the next
  failure will show its cause. Cause unknown.
- **Scenario `cobalt-group-bfsi-financial-impact`** was uncommitted for a period
  and was signed and committed by the other session (`24f0c9e8`); the ledger has
  been regenerated to include it.

## Open

1. Rebuild and deploy to staging.
2. Run `collection-staging-exfil` and one new scenario on the lab VM; compare each
   run's stored results with its chain report.
3. Browser check of the chain panel.
4. Campaign table for correlation: on hold, pending step 2.
