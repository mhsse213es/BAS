# Audspect / BAS — Focus Areas: Turning Gaps into Moats

**Date:** 2026-09-26
**Premise (corrected):** We are *not* the only on-prem BAS (open-source Caldera/ART/Infection Monkey and commercial Picus/AttackIQ/SafeBreach all offer on-prem/hybrid). The defensible position is: **the only air-gapped, compliance-native BAS purpose-built for Indian BFSI.** Focus every investment there.

---

## Focus areas — convert each gap into a strength

### 1. Air-gapped content velocity (fixes our #1 weakness on our own terms)
Content freshness is the giants' hardest moat — but theirs is *cloud-delivered*, useless in an air-gap. Own what they can't do:
- Build a **signed offline threat-content-pack pipeline** (we already have `ti-bundle` + RSA signing + integrity infra). Publish a new pack weekly / on major threat, deliverable by USB / internal repo, cryptographically verified on ingest.
- Make it measurable: **"emerging-threat coverage in your air-gapped environment within N days, no internet required."** No SaaS vendor can promise that for a true air-gap.

### 2. Indian regulatory depth (crown jewel — widen it)
- Complete **IRDAI** and **CERT-In** (currently 0 scenarios), finish **ISO 27001:2022** control mapping, keep RBI/SEBI cited to circulars.
- Auto-generate the **exact audit-pack format** auditors/regulators expect, backed by the HMAC hash-chained evidence chain. Goal: the report a bank hands straight to a SEBI/RBI auditor — become the tool auditors *recognize*.

### 3. Detection engineering for the SOC stacks our market runs
Picus wins on vendor-specific detection content. We don't need 40 products — just the ones Indian BFSI SOCs run: **Splunk, QRadar, Sentinel, CrowdStrike, Securonix, Elastic.** Ship deployable rules + "here's the gap and the exact rule to close it," delivered on-prem. Deep-but-narrow beats broad-but-cloud here.

### 4. Compliance-as-continuous-evidence (reframe the category)
Position against point-in-time audits and annual red teams: **continuous control validation + control-drift detection + always-current audit evidence.** We already have control-health, drift-analytics, and the evidence chain — package the story: *"your compliance posture, provable on any day, offline."*

### 5. Frictionless deployment in constrained/air-gapped environments
Turn "on-prem is hard" into "1-day install": hardened appliance ISO / k3s, works with no internet, sane defaults, lean-IT-team friendly. Bank IT teams are small and cautious — deployment simplicity is a real differentiator.

### 6. Deep BFSI sector scenarios nobody else has
UPI fraud (have one), SWIFT/SFMS, core-banking, ATM/switch, NPCI rails, insurance-specific fraud. Sector-specific attack content is a moat the horizontal giants won't build for India.

### 7. Product self-assurance (existential, not optional)
We sell to banks. Fix the assessment's Wave 0–2 (secrets, agent trust model), then pursue the assurance a BFSI buyer demands — pen-test attestation, eventually SOC2 / ISO / CERT-In empanelment. Both a differentiator vs sloppy competitors and table stakes for the buyer.

### 8. TCO / licensing
Predictable on-prem / perpetual pricing vs recurring SaaS subscriptions — a concrete CFO-level buy reason in the mid-market.

---

## What to deliberately NOT chase
- Email-gateway / web-gateway / WAF vectors (giant breadth war — skip for now).
- Global multi-region SaaS / multi-tenancy (unless we pivot to SaaS; RLS is off anyway).
- The "Mythos" autonomous adversary as a near-term build — keep it as R&D vision, not roadmap; it distracts from the wedge.

---

## The one-line strategy
Every focus area above deepens **air-gapped + compliance-native + Indian BFSI**, instead of fighting the giants where they're strongest. Own the market they under-serve; don't enter the feature war you can't win.
