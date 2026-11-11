# REQ-021 MSRC Spike: Windows Critical KEVs and vendor fixed builds

**Status:** Measurement result. Not a verdict on any endpoint.
**Run:** 2026-11-10 (UTC), against the same KEV snapshot (`catalogVersion 2026.11.09`) and NVD bulk snapshot as the Ubuntu spike.

## 1. Question

For Windows Critical KEVs (CVSS 9.0-10.0), does MSRC's security-update data provide a vendor fixed build that a version check could compare against?

## 2. Method

- Critical population and CVSS: the same as the Ubuntu spike (NVD CVSS v3.1 Primary, else v3.0 Primary; Critical = 9.0-10.0).
- Windows scope: Microsoft Critical KEVs whose affected product is Windows itself or a Windows component (for example Remote Desktop Services, SMBv3, Windows DNS Server, Hyper-V, Windows Search, .NET Framework, IIS on Windows Server). SharePoint, Office, Forefront, and cloud services are out of scope because they have no Windows OS fixed build.
- Source: MSRC CVRF documents for the NVD published month of each CVE, from `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{yyyy-Mon}`.
- Fixed build = a remediation whose `FixedBuild` field is set, for a product whose name contains "Windows".

## 3. Results

| Measure | Count |
|---|---|
| Microsoft Critical KEVs | 13 |
| Of those, Windows OS-scope | **7** (CVE-2017-7269, CVE-2017-8543, CVE-2019-0708, CVE-2020-0646, CVE-2020-0796, CVE-2020-1040, CVE-2020-1350) |
| Windows OS-scope with a vendor Windows fixed build | **0** |
| Windows OS-scope with KB article only | 7 |

Every in-scope CVE is from 2017 to 2020. Their CVRF documents are CVRF 1.1 XML. Remediations carry KB numbers (for example `4558998` for CVE-2020-1350), but none has a `FixedBuild` value for a Windows product.

The modern CVRF format does carry Windows fixed builds. The 2026-Oct document contains 31,269 Windows remediations, of which 12,346 have a `FixedBuild` (for example `10.0.22631.7652` for Windows 11 23H2 ARM64, KB `5126653`). The vendor data path works for recent Microsoft advisories. It does not cover the historical Critical Windows KEVs.

## 4. Why the Windows Critical population is so small

The approved Critical definition (CVSS 9.0-10.0) removes most Windows KEVs. Across the 178 KEVs whose product is Windows:

| CVSS band (NVD v3) | Count |
|---|---|
| Critical (9.0-10.0) | 2 |
| High (7.0-8.9) | 60 |
| Medium or Low | 3 |
| No v3 score (excluded) | 113 |

Most Windows exploited vulnerabilities are rated High, for example privilege escalation at 7.8. MSRC's own severity is also not the same as CVSS. A Critical-only scope therefore gives a Windows population of seven CVEs, all of them old. It is too small to measure a coverage rate, and it does not represent the Windows exposure that matters in practice.

## 5. What the spike establishes

1. **For the approved Critical scope, Windows coverage is 0 of 7 vendor fixed builds.** The seven are historical, and their CVRF documents do not carry Windows fixed builds.
2. **The vendor data source works for recent Microsoft advisories.** It cannot be assumed for older ones, so the spike must check each source's era.
3. **The scope choice dominates the result.** A Critical-only Windows measurement is not useful. A decision is needed on whether Windows exposure should use High as well, or MSRC severity instead of CVSS.

## 6. Decisions needed from the owner

1. Keep Critical as CVSS 9.0-10.0 for Windows, which yields 7 historical CVEs, or widen the Windows scope to High (CVSS 7.0-8.9)?
2. Accept KB-only remediations as "NOT_RESOLVABLE" for pre-2023 advisories, which gives UNKNOWN for those CVEs, or source KB-to-build data from Microsoft's update history?
