# bas-caldera image

Extends `ghcr.io/mitre/caldera:latest` with the CTID adversary-emulation
library baked in (the `emu` plugin), so APT kill-chains load air-gapped.

- Built by `packaging/windows-build.ps1` on the internet-connected Windows host.
- The clone happens inside the Docker build layer — nothing touches the host FS.
- The library contains REAL offensive payloads. The resulting image (and the
  `bas-caldera-*.tar` in the bundle) WILL be flagged by AV/EDR. See
  `docs/CALDERA_EMU.md` for the client AV-allowlist guidance.
- Rebuild when upgrading Caldera or refreshing the emulation library.
