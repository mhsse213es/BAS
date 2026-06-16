// Package detect correlates collected endpoint alerts into per-technique
// detection verdicts and scores. Pure, server-side; the agent never classifies.
package detect

import "regexp"

// edrProviderRE matches known EDR/AV event-provider names (case-insensitive,
// regex — vendors rename providers between versions; substrings suffice).
var edrProviderRE = regexp.MustCompile(`(?i)(microsoft )?defender|antimalware|trellix|mcafee|crowdstrike|falcon|sentinelone|sophos|trend ?micro|apex one|palo alto|cortex|elastic endpoint|rapid7|insight|fortinet|fortiedr|carbon black|sense`)

// IsEDRProvider reports whether an event provider name looks like an EDR/AV tool.
func IsEDRProvider(provider string) bool { return edrProviderRE.MatchString(provider) }
