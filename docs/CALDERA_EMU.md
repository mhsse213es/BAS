# Caldera Adversary Emulation (emu)

The platform ships Caldera with the CTID adversary-emulation library baked in,
so full APT kill-chains run **fully air-gapped** — no runtime download.

## What it adds
- Hundreds of additional Caldera **abilities** and ~39 **adversary profiles**
  (sequenced, multi-step chains): APT29, FIN6, FIN7, menuPass, OilRig, Sandworm,
  Carbanak, Wizard Spider, and more — on top of the ~166 stockpile abilities.
- This is **distinct from Atomic Red Team**. The orchestrator runs ART natively
  (~1210 Windows atomics) for technique breadth; emu provides sequenced APT
  chains. They are complementary, not duplicates — do not add their counts.

## Safety model (read before running)
- emu chains include **real offensive payloads**. Any Caldera ability that ships
  a payload is tagged **lab-only** by the orchestrator: it runs **only in lab
  mode** (isolated range, second confirmation) and is dropped in posture and
  telemetry. Payload-free emu abilities run in telemetry and lab.
- This gating is server-enforced — the agent never decides fidelity.

## Client AV/EDR allowlist (REQUIRED on delivery)
- The install bundle's `images/bas-caldera-*.tar` contains **real offensive
  tooling** and **will be flagged / quarantined by AV/EDR**. Before the bundle is
  transferred or extracted on the client's network, the client must allowlist:
  - the bundle file path / extraction directory, and
  - the Docker data-root (where the `bas-caldera` image layers are loaded).
- Coordinate this with the client's security team as part of onboarding. Treat it
  as a delivery prerequisite, not an afterthought — a bank's EDR will otherwise
  quarantine the bundle on arrival.

## Rebuilding the library
- The image is built by `packaging/windows-build.ps1` on the internet-connected
  Windows host (the only place the library is cloned). Rebuild when upgrading
  Caldera or to refresh the emulation plans.
- The shipped library commit SHA is printed in the `docker build` output
  (`adversary-emulation-library @ <sha>`). **Record it in the release notes** for
  supply-chain auditability.

## Verifying after deploy
- Settings → Caldera shows the ability count; a Caldera scenario's picker shows
  the full ability list. Post-deploy the count rises from ~166 to several hundred,
  and adversary profiles appear.
