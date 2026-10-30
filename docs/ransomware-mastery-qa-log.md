# Ransomware Mastery QA Log

Last updated: 2026-10-30. Head: `74b376ec`.

## Verified (orchestrator, automated)
- Full `internal/api` suite passed (1649 s), including the Recovery change.
- Targeted packages pass: `rwdetect`, `rwcontain`, `rwrecover`, `rwevidence`, `admatrix`, `scenario`, `vendors/crowdstrike`, `models`.
- Per-capability wiring with tests: Detection (`9b1e25d6`), Containment (`1a4b3439`), Recovery (`74b376ec`).
- Step metadata now carries `action_key` (`45406fc4`).

## Open: needs staging or a live environment
- **Staging deploy:** `install.sh --upgrade` on the orchestrator (not `--install`). Needed for the Akira step 8b and the DCSync fix to take effect.
- **Live Recovery check:** run the Akira chain on the lab endpoint and confirm the Recovery row matches the copy count before and after.
- **Connector choice:** Detection and Containment have no real tenant yet. Options are Sentinel, Defender XDR, Splunk, or Elastic.
- **CrowdStrike field verification:** the Hosts API status field and values (`contained`, `normal`, `containment_pending`, `lift_containment_pending`) are unconfirmed against a live tenant.
- **CrowdStrike prerequisites:**
  - The Falcon sensor must be installed and enrolled on the test endpoint. Without it, the device lookup returns "device not found" and Containment stays inconclusive.
  - The tenant needs an API client with read access to hosts. Add the containment scope if the isolate and release actions are used.

## Open: still fake
- **Prevention:** needs a real control-response source (EDR or agent evidence).
- **DataProtection:** needs a real DLP result source.

## Known limits (by design, documented)
- Containment is a point-in-time read of device status, not state at attempt time.
- Recovery treats a fall in shadow-copy count as loss of the targeted copy. Stage 8 deletes the oldest copy, so this is an approximation.
