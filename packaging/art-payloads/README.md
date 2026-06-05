# ART external payloads (build-host staging)

Some Atomic Red Team atomics invoke an **external binary** (e.g. `gsecdump.exe`,
`mimikatz.exe`, `PsExec.exe`). These are **not** part of the atomic-red-team git
repo — the upstream runner downloads them per-atomic from third-party URLs at
prerequisite time — and most are offensive hacktools flagged by AV.

Because clients are air-gapped and the install must not fetch hacktools on its
own, payloads are added **once here, on the build host**, and baked into every
`bas-install` / air-gap bundle automatically. The client does nothing.

## How to use

1. On the build host, drop the binaries this release's scenarios need into this
   folder, named exactly as the atomics reference them:

   ```
   packaging/art-payloads/gsecdump.exe
   packaging/art-payloads/mimikatz.exe
   ```

   (The filename must match the basename in the atomic, e.g. `gsecdump.exe`.
   Matching is case-insensitive.)

2. Build the bundle as usual:

   ```
   bash packaging/build.sh 1.6.0        # compose bundle
   bash packaging/airgap/pack.sh 1.6.0  # air-gap bundle
   ```

   The build copies this folder into the bundle's `art-payloads/`, which the
   compose file bind-mounts to `/art-payloads` in the orchestrator. At run time
   the server streams the matching payload to the agent's temp dir (Caldera
   style) — nothing is ever placed on the endpoint.

3. Any atomic whose payload is **not** in this folder is **skipped cleanly**
   (result = SKIPPED, naming the missing file) rather than failing.

## Notes

- Binaries here are **git-ignored** (the repo's recursive `*.exe` rule plus the
  `.gitignore` entry for this folder), so hacktools are never committed.
- Your build host's AV may quarantine these files — add an exclusion for this
  folder on the build machine only.
- Keep this curated to the payloads your shipped scenarios actually use; you do
  not need the entire ART ExternalPayloads set.
