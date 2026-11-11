# REQ-021 technical cross-check of Ubuntu mappings (Claude's check, not a review)

**Date:** 2026-11-10. **Method:** for each of the 19 `UBUNTU-` rows in `reviewed_mappings.yaml`, fetch Ubuntu's public CVE page and check that each recorded fixed-version string appears on it. Script: `req021-spike/crosscheck.py`.

**Limit:** a MATCH only means the string appears on the page. It does not check that the string is a valid fix for that package. A string can appear on the page and still be the wrong kind of value (see CVE-2022-26486).

## Results

| CVE | Result | Note |
|---|---|---|
| CVE-2020-12641 | MATCH | |
| CVE-2021-1870 | MATCH | |
| CVE-2021-1871 | MATCH | |
| CVE-2021-40438 | MATCH | |
| CVE-2021-44026 | MATCH | |
| CVE-2021-44228 | MATCH | |
| CVE-2021-45046 | MATCH | |
| CVE-2022-0543 | MATCH | |
| CVE-2022-22965 | MATCH | |
| CVE-2022-26486 | MATCH | The string matches, but jammy's value is a snap transition string. Already decided: jammy excluded, focal kept. |
| CVE-2022-46169 | MATCH | |
| **CVE-2023-46604** | **MISMATCH** | jammy `5.16.1-1ubuntu0.1~esm1` is not on the page. The page lists jammy as `5.16.1-1ubuntu0.1`. The `~esm1` variant is not supported by the public record. The `5.16.1-1ubuntu0.1` entry does match. |
| CVE-2024-38475 | MATCH | |
| CVE-2024-42009 | MATCH | |
| CVE-2024-9680 | MATCH | |
| CVE-2025-24201 | MATCH | |
| CVE-2025-24813 | MATCH | |
| CVE-2026-109618 | MATCH | |
| CVE-2026-111497 | MATCH | |

**Totals:** 18 match, 1 mismatch.

## Open follow-ups from this check

1. **CVE-2023-46604 (ActiveMQ, jammy):** the `~esm1` value should not be kept as a fixed version unless an ESM source confirms it. This is a finding. The decision belongs to the curator.
2. **Transient fetch failures:** three pages returned 503 or 504 on the first run and succeeded on retry. The results above come from the successful run.
