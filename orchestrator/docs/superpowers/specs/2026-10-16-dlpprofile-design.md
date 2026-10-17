# dlpprofile — DLP Mastery industry/regional profile package

## Intent and why

`dlp.txt` (repo root) is the enterprise blueprint for DLP BAS Mastery. Section 4
requires India/UAE industry-specific data profiles, control expectations, and
evidence — "a generic credit-card regex test is not adequate for a bank."
This is Phase 1, priority 1 of the DLP Mastery initiative (user-ranked ahead
of fixtures/evidence-model/capability-model/Purview connector; see chat
2026-10-16 and memory `project_dlp_mastery_initiative`).

The project already solved this exact problem twice: `internal/avprofile`
(AV/NGAV BAS Mastery) and `internal/wafprofile` (WAF BAS Mastery) both map a
named industry or region to a subset of real, existing scenario coverage,
with an explicit `Verified`/`Unverified` compliance-reference honesty flag
and a `ValidateAgainstCatalog` check that makes it structurally impossible to
reference a vector/scenario that doesn't actually exist. `dlpprofile` is a
third instance of that same pattern — not a new design.

## Goals

- A `dlpprofile` package, structurally identical to `avprofile`: `Profile`,
  `ComplianceReference`, `VerificationStatus` (`Verified`/`Unverified`),
  `ProfileKind` (`industry`/`regional`), `NewProfile`, `NewComplianceReference`,
  `ValidateAgainstCatalog`, `ControlObjectiveCoverage`/`WithControlObjectives`
  for the honest-gap pattern.
- A seed catalog (`AudspectDLPProfileCatalog()`) covering the industries named
  in `dlp.txt` §4: BFSI/NBFCs, Healthcare, Manufacturing/engineering,
  Government/legal/professional-services/HR, IT/SaaS/BPO/telecom — plus
  India and UAE cross-industry regional baselines, each with
  `VerificationStatus: Unverified` compliance references (framework name only,
  same honesty bar `avprofile` already set — RBI/SEBI/DPDP for India BFSI,
  UAE Central Bank for UAE BFSI, Indian health-data rules + UAE
  federal/emirate health rules for Healthcare, etc., per the regulatory
  mapping `dlp.txt` names for each sector).
- Every profile's `VectorIDs` must validate against the **real, current**
  set of DLP scenario IDs (ground truth below), via the same
  `ValidateAgainstCatalog`-style check `avprofile` uses — so a profile can
  never claim coverage of a scenario that doesn't exist.
- Full unit test coverage mirroring `avprofile`'s test suite exactly
  (construction validation, duplicate rejection, empty-field rejection,
  `TestAudspectDLPProfileCatalog_EveryComplianceReferenceIsUnverifiedWithANote`
  equivalent, catalog-validation round-trip).

## Non-goals (explicitly out of scope for this package)

- **No `dlpcatalog` package.** The blueprint's `dlpcatalog` is a much bigger
  thing (capability requirements, data-profile versioning, full scenario
  registry) — not this phase's job, and not needed to validate against real
  scenario IDs (see "Builder's call" below).
- **No new scenario content.** `dlpprofile` references scenarios that already
  exist; it does not add DLP-POL/DLP-CLS/DLP-ENF coverage, classification/
  transformation-matrix tests, or any new channel. Those are later,
  separately-scoped phases.
- **No fixture centralization, evidence-model changes, or Purview connector
  work.** Those are priorities 2-5, each its own package/change, per the
  user's explicit instruction not to bundle them with this one.
- **No UI/console surface.** Whether/how profiles render in the dashboard is
  not decided here (AV/WAF's own console integration, if any, is a separate
  precedent to check when that question actually comes up — not blocking
  this package).

## Anti-goals (would make this a failure even if it "works")

- A profile that claims coverage of a DLP control dimension (classification
  quality, policy enforcement, detection/response) that the current scenario
  set cannot actually back up. Every `VectorIDs` entry must trace to a real,
  executable scenario ID — never an aspirational one.
- Silently reusing AV/WAF's `ComplianceReference` wording/severity claims for
  DLP's different regulatory surface (RBI Cyber Security Framework is an AV
  precedent for BFSI malware controls, not DLP — DLP's BFSI reference should
  be its own, drawn from `dlp.txt`'s own regulatory-mapping paragraph).
- Forcing a mapping for an industry/dimension that has no honest match
  (mirrors `avprofile`'s Government 3/6-mapped-with-recorded-gaps and MSP
  permanently-0/5 precedent) — a thin or gapped profile is correct and
  expected at this phase, not a defect to paper over.

## Constraints

- Package lives at `orchestrator/internal/dlpprofile`, following the
  existing `internal/avprofile`/`internal/wafprofile` sibling-package
  convention — never folded into `internal/reporting` or any sink package.
- Must compile and pass tests standalone; this phase makes **no changes** to
  any existing file outside the new package (confirmed scope boundary from
  the user: "Existing exfiltration scenarios continue to pass regression
  tests").
- No vendor-validated claims: nothing in this package may describe any
  scenario as "vendor-validated" or similar — ground truth for every
  existing DLP scenario today is the sink-receipt/local-marker model, not a
  real vendor API (see `project_dlp_mastery_initiative` memory, gap #1).

## Builder's call (decided here, not re-litigated)

**What does `VectorIDs` validate against, given there is no `dlpcatalog`?**
`avprofile`/`wafprofile` both validate against a real catalog package
(`avcatalog.AudspectAVAttackCatalog()` / `wafcatalog`'s equivalent). DLP has
no such package yet, and building one is explicitly out of scope (see
Non-goals). The real, current ground truth is the set of scenario IDs that
actually exist in `scenarios/dlp-*.yaml`:

```
dlp-exfiltration-validation
dlp-exfiltration-sink-https
dlp-exfiltration-dns-tunnel
dlp-exfiltration-sftp
dlp-exfiltration-smtp
dlp-exfiltration-cloud-storage
dlp-exfiltration-webhook
dlp-exfiltration-coderepo
dlp-exfiltration-telnet
dlp-exfiltration-multichannel
```
(confirmed via `grep ^id: scenarios/dlp-*.yaml`, 2026-10-16 — 9 standalone +
1 bundle, not the 11 a stale earlier estimate suggested).

Resolution: `dlpprofile` defines its own minimal, real ground-truth list —
`RealDLPScenarioIDs() []string` returning exactly the 10 IDs above, in its
own file (`dlpprofile/scenarios.go`), analogous in *purpose* to
`avcatalog.AudspectAVAttackCatalog()` but deliberately not named or shaped
like a catalog package, since it carries none of a catalog's other
responsibilities. `ValidateAgainstCatalog`'s signature changes from
`(profile Profile, catalog []avcatalog.Vector)` to
`(profile Profile, realScenarioIDs []string)` — simpler than avprofile's
version since there's no `Vector` struct to extract `.ID` from, just a flat
ID list. `VectorIDs` on a DLP `Profile` therefore holds scenario IDs
directly (e.g. `"dlp-exfiltration-sftp"`), not a synthetic per-vector ID
scheme — there is no finer-grained vector concept in DLP today than "the
scenario". When DLP-POL/CLS/ENF scenarios land in a later phase, this list
grows; no profile-package structural change is needed.

**Consequence accepted:** because today's real scenario set only covers
exfiltration channels (not policy/classification/enforcement), most
industry profiles in this seed catalog will be visibly thin and should use
`ControlObjectiveCoverage`/`WithControlObjectives` to record named gaps
honestly, the same way AV's Government profile recorded 3/6-mapped — this is
expected, not a sign the package is incomplete.

**Sharper gap found during builder-check review, resolved here (2026-10-16):**
all 10 real scenarios test the *identical* hardcoded synthetic payload —
fabricated PAN/Aadhaar/SWIFT/UPI/credit-card, confirmed by reading every
scenario's own description text. That payload is BFSI/India-shaped. No
healthcare (patient/lab record), manufacturing (CAD/source-code/IP),
government (citizen record/case file), or UAE-shaped (Emirates ID, IBAN)
test data exists anywhere in the real scenario set. So the channel-coverage
gap this spec already anticipated is not the only gap: even where a channel
genuinely exists (e.g. `dlp-exfiltration-sftp`), it has only ever been
*exercised* with BFSI/India data, not with the data type that industry
actually cares about.

Resolution: for every industry/region other than the BFSI/NBFC/India
profiles (whose real payload the scenarios already match), `VectorIDs`
still lists the real channel-level scenario IDs (channel delivery mechanics
are genuinely industry-agnostic — an SFTP exfil channel works the same
regardless of payload), but `ControlObjectiveCoverage` must record an
explicit named gap for "data-type/classification matching this sector's
actual sensitive-data profile" separately from the channel-level coverage —
mirroring AV Government's 3/6-gap pattern, just applied one level more
granularly (gap is in payload fidelity, not channel existence). This applies
to Healthcare, Manufacturing, Government/Legal/HR, IT/SaaS/BPO/telecom, and
**UAE** (its regional baseline has the same BFSI/India-payload-only
problem, sharper since `dlp.txt` names UAE-specific fixtures — Emirates ID,
IBAN — that don't exist in any scenario today). UAE still gets a minted
`DLPPROFILE-UAE` (not the MSP no-mint treatment) because, unlike MSP's
genuine 0/5 vector applicability, UAE's channel-level vectors (SFTP,
webhook, cloud-storage, etc.) are real and applicable regardless of payload
shape — only the payload-fidelity dimension is gapped, which
`ControlObjectiveCoverage` already has a slot for. Only BFSI, NBFC, and the
India regional baseline get a flat, ungapped `VectorIDs`-only profile, since
their real payload is the one the scenarios actually test.

**Also found and resolved:** `dlp-exfiltration-multichannel.yaml`'s own
description claims it "combines every DLP exfiltration channel built so
far," but it actually contains only 9 technique steps (the 5 agent-native
channels + HTTPS/DNS-tunnel/SFTP/SMTP) and omits cloud-storage, webhook,
coderepo, and telnet entirely — a staleness bug in the scenario's own
description, independent of this package. Rule for this package: no profile
may cite `dlp-exfiltration-multichannel` in `VectorIDs` or rationale text as
evidence of broad/full-channel coverage; cite the specific individual
scenario IDs that actually matter per industry instead (which the
Builder's-call examples below already do). The scenario description's own
staleness is a separate, tiny, not-bundled follow-up — noted in
`project_dlp_mastery_initiative` memory, not fixed by this package.

## What's left to the builder

- Exact wording of each industry's rationale/provenance strings and which
  of the 10 scenario IDs each industry profile selects — informed by
  `dlp.txt` §4's own per-industry bullet lists (e.g. BFSI → KYC/payment-card
  data → `dlp-exfiltration-cloud-storage`, `-webhook`, `-sftp`, `-smtp` as
  the channels a bank's exported customer data would realistically leave
  through; Manufacturing → CAD/source-code/IP → `-coderepo`, `-cloud-storage`,
  `-sftp`; IT/SaaS/BPO → source code/API creds → `-coderepo`, `-webhook`).
- Which specific named regulatory frameworks go in each
  `ComplianceReference` (RBI/SEBI/DPDP for India BFSI; UAE Central Bank
  requirements for UAE BFSI; India/UAE health-data rules for Healthcare;
  CERT-In for Manufacturing; no named framework for Government/Legal/HR or
  IT/SaaS beyond a cross-industry DPDP/UAE baseline, mirroring how AV left
  Government's framework as a disclosed best-effort NIST substitute) — all
  `Unverified`, framework-name-only, same honesty bar as `avprofile`.
- Whether India and UAE get one combined regional profile per industry or
  two separate ones (`DLPPROFILE-BFSI-INDIA` / `DLPPROFILE-BFSI-UAE`) versus
  AV's model of separate flat `DLPPROFILE-INDIA`/`DLPPROFILE-UAE`
  cross-industry baselines plus industry profiles that aren't region-split.
  Builder default: follow AV's exact shape (industry profiles unsplit by
  region + two standalone regional baseline profiles: `DLPPROFILE-INDIA`,
  `DLPPROFILE-UAE`) for structural consistency, since `dlp.txt` itself
  treats India/UAE as cross-cutting regional baselines layered over the same
  industries, not forty distinct per-region-per-industry profiles.
