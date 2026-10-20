// Package dlpprofile is a bundling/reference layer covering dlp.txt §4's
// "industry-specific mastery: India and UAE" item, mirroring
// internal/avprofile and internal/wafprofile's own pattern exactly.
package dlpprofile

// RealDLPScenarioIDs is the ground truth for which DLP scenario IDs
// actually exist under scenarios/dlp-*.yaml today (confirmed via
// `grep ^id: scenarios/dlp-*.yaml`, 2026-10-16/17). There is no
// dlpcatalog package to validate Profile.VectorIDs against -- building
// one is out of scope for this package (see the design spec's
// Non-goals) -- so this function is dlpprofile's own minimal substitute
// for avcatalog.AudspectAVAttackCatalog()/wafcatalog's equivalent,
// carrying none of a catalog's other responsibilities.
func RealDLPScenarioIDs() []string {
	return []string{
		"dlp-exfiltration-validation",
		"dlp-exfiltration-sink-https",
		"dlp-exfiltration-dns-tunnel",
		"dlp-exfiltration-sftp",
		"dlp-exfiltration-smtp",
		"dlp-exfiltration-cloud-storage",
		"dlp-exfiltration-webhook",
		"dlp-exfiltration-coderepo",
		"dlp-exfiltration-telnet",
		"dlp-exfiltration-multichannel",
		"dlp-exfiltration-ai-prompt",
		"dlp-exfiltration-db-export",
		"dlp-exfiltration-devtools",
		"dlp-exfiltration-email-recipients",
	}
}
